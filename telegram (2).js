const { TelegramClient } = require('telegram');
const { StringSession }  = require('telegram/sessions');
const { Api }            = require('telegram');

const API_ID    = parseInt(process.env.TELEGRAM_API_ID   || '38211066');
const API_HASH  = process.env.TELEGRAM_API_HASH          || '8cd8f7539e9d4830727fd910374a8b20';
const ADMIN_KEY = process.env.ADMIN_KEY                  || 'admin123';

async function makeClient(sessionStr = '') {
  const client = new TelegramClient(
    new StringSession(sessionStr),
    API_ID, API_HASH,
    { connectionRetries: 5, useWSS: true }
  );
  await client.connect();
  return client;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-admin-key');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body   = req.body || {};
  const action = body.action || req.query.action;

  // Protected routes
  if (['groups','members'].includes(action) && req.headers['x-admin-key'] !== ADMIN_KEY)
    return res.status(401).json({ error: 'Unauthorized' });

  try {

    /* ─── STATUS ─────────────────────────────────── */
    if (action === 'status') {
      const sess = process.env.TELEGRAM_SESSION || '';
      if (!sess) return res.json({ connected: false });
      const client = await makeClient(sess);
      const ok = await client.isUserAuthorized();
      if (ok) {
        const me = await client.getMe();
        await client.disconnect();
        return res.json({
          connected: true,
          name: [me.firstName, me.lastName].filter(Boolean).join(' '),
          username: me.username || ''
        });
      }
      await client.disconnect();
      return res.json({ connected: false });
    }

    /* ─── SEND CODE ──────────────────────────────── */
    // KEY FIX: session কে client থেকে save করে client এ পাঠাই
    // পরের request এ same session restore করব যাতে code expire না হয়
    if (action === 'send-code') {
      const { phone } = body;
      if (!phone) return res.status(400).json({ error: 'Phone number দাও' });

      const client = await makeClient(''); // fresh session
      const result = await client.sendCode(
        { apiId: API_ID, apiHash: API_HASH },
        phone
      );
      // এই partial session টা save করা জরুরি — এটা ছাড়া OTP কাজ করবে না
      const partialSession = client.session.save();
      await client.disconnect();

      return res.json({
        success: true,
        phoneCodeHash: result.phoneCodeHash,
        partialSession             // client এ store হবে, verifyCode এ ফেরত আসবে
      });
    }

    /* ─── VERIFY CODE ────────────────────────────── */
    if (action === 'verify-code') {
      const { phone, code, phoneCodeHash, partialSession } = body;
      if (!phone || !code || !phoneCodeHash || !partialSession)
        return res.status(400).json({ error: 'Missing fields' });

      // KEY FIX: partialSession দিয়ে same client restore করছি
      const client = await makeClient(partialSession);

      try {
        await client.invoke(new Api.auth.SignIn({
          phoneNumber:   phone,
          phoneCodeHash: phoneCodeHash,
          phoneCode:     code.trim()
        }));
        const session = client.session.save();
        await client.disconnect();
        return res.json({ success: true, session });

      } catch (err) {
        if (err.errorMessage === 'SESSION_PASSWORD_NEEDED') {
          // 2FA দরকার — এই session টাও save করে রাখি
          const partialSession2FA = client.session.save();
          await client.disconnect();
          return res.json({ success: false, need2FA: true, partialSession2FA });
        }
        if (err.errorMessage === 'PHONE_CODE_EXPIRED')
          return res.json({ success: false, error: 'OTP মেয়াদ শেষ! আবার OTP পাঠাও।' });
        if (err.errorMessage === 'PHONE_CODE_INVALID')
          return res.json({ success: false, error: 'OTP ভুল! আবার দাও।' });
        throw err;
      }
    }

    /* ─── VERIFY 2FA ─────────────────────────────── */
    if (action === 'verify-2fa') {
      const { password, partialSession2FA } = body;
      if (!password || !partialSession2FA)
        return res.status(400).json({ error: 'Missing fields' });

      const client = await makeClient(partialSession2FA);
      const { computeCheck } = require('telegram/Password');
      const pwdInfo = await client.invoke(new Api.account.GetPassword());
      const check   = await computeCheck(pwdInfo, password);
      await client.invoke(new Api.auth.CheckPassword({ password: check }));
      const session = client.session.save();
      await client.disconnect();
      return res.json({ success: true, session });
    }

    /* ─── GET GROUPS ─────────────────────────────── */
    if (action === 'groups') {
      const sess = process.env.TELEGRAM_SESSION || '';
      if (!sess) return res.status(401).json({ error: 'Not connected' });
      const client = await makeClient(sess);
      if (!(await client.isUserAuthorized())) {
        await client.disconnect();
        return res.status(401).json({ error: 'Session expired. Re-login করো।' });
      }
      const dialogs = await client.getDialogs({ limit: 200 });
      const groups  = dialogs
        .filter(d => d.isGroup || d.isChannel)
        .map(d => ({
          id:    d.id.toString(),
          title: d.title || 'Unnamed',
          type:  d.isChannel ? 'channel' : 'group'
        }));
      await client.disconnect();
      return res.json({ success: true, groups });
    }

    /* ─── COLLECT MEMBERS ────────────────────────── */
    if (action === 'members') {
      const { groupId, days=7, minMessages=1, maxScan=500 } = body;
      if (!groupId) return res.status(400).json({ error: 'Group ID দাও' });

      const sess = process.env.TELEGRAM_SESSION || '';
      if (!sess) return res.status(401).json({ error: 'Not connected' });

      const client = await makeClient(sess);
      if (!(await client.isUserAuthorized())) {
        await client.disconnect();
        return res.status(401).json({ error: 'Session expired' });
      }

      const cutoff  = Math.floor((Date.now() - parseInt(days)*86400000) / 1000);
      const entity  = await client.getEntity(groupId);
      const memberMap = {};
      let offsetId = 0, fetched = 0, done = false;
      const limit = Math.min(parseInt(maxScan), 500);

      while (!done && fetched < limit) {
        const msgs = await client.getMessages(entity, {
          limit: 100,
          offsetId: offsetId || undefined
        });
        if (!msgs || !msgs.length) break;

        for (const msg of msgs) {
          if (msg.date < cutoff) { done = true; break; }
          const sender = msg.sender;
          if (!sender || sender.bot || !sender.username) continue;
          const key = sender.username.toLowerCase();
          if (!memberMap[key]) {
            memberMap[key] = {
              username:     sender.username,
              firstName:    sender.firstName || '',
              messageCount: 0
            };
          }
          memberMap[key].messageCount++;
        }
        offsetId = msgs[msgs.length-1].id;
        fetched += msgs.length;
        if (msgs.length < 100) break;
      }

      let members = Object.values(memberMap)
        .filter(m => m.messageCount >= parseInt(minMessages))
        .sort((a,b) => b.messageCount - a.messageCount);

      await client.disconnect();
      return res.json({ success:true, members, total:members.length, scanned:fetched, groupTitle:entity.title });
    }

    return res.status(400).json({ error: 'Invalid action: ' + action });

  } catch (err) {
    console.error('[ERROR]', err.message);
    return res.status(500).json({ error: err.message || 'Server error' });
  }
};
