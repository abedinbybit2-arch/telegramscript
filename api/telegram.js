const { TelegramClient } = require('telegram');
const { StringSession }  = require('telegram/sessions');
const { Api }            = require('telegram');

const API_ID    = parseInt(process.env.TELEGRAM_API_ID   || '38211066');
const API_HASH  = process.env.TELEGRAM_API_HASH          || '8cd8f7539e9d4830727fd910374a8b20';
const ADMIN_KEY = process.env.ADMIN_KEY                  || 'admin123';

async function makeClient(sessionStr = '') {
  const client = new TelegramClient(new StringSession(sessionStr), API_ID, API_HASH, { connectionRetries: 5, useWSS: true });
  await client.connect();
  return client;
}

async function getAuthedClient() {
  const sess = process.env.TELEGRAM_SESSION || '';
  if (!sess) throw new Error('Not connected. Please login first.');
  const client = await makeClient(sess);
  if (!(await client.isUserAuthorized())) throw new Error('Session expired. Re-login করো।');
  return client;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-admin-key');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body   = req.body || {};
  const action = body.action || req.query.action;

  if (action === 'validate-key') {
    if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ valid: false, error: 'ভুল Admin Key!' });
    return res.json({ valid: true });
  }

  const publicActions = ['send-code','verify-code','verify-2fa'];
  if (!publicActions.includes(action) && req.headers['x-admin-key'] !== ADMIN_KEY)
    return res.status(401).json({ error: 'Unauthorized' });

  try {

    if (action === 'status') {
      const sess = process.env.TELEGRAM_SESSION || '';
      if (!sess) return res.json({ connected: false });
      const client = await makeClient(sess);
      const ok = await client.isUserAuthorized();
      if (ok) { const me = await client.getMe(); await client.disconnect(); return res.json({ connected:true, name:[me.firstName,me.lastName].filter(Boolean).join(' '), username:me.username||'' }); }
      await client.disconnect();
      return res.json({ connected: false });
    }

    if (action === 'send-code') {
      const { phone } = body;
      if (!phone) return res.status(400).json({ error: 'Phone number দাও' });
      const client = await makeClient('');
      const result = await client.sendCode({ apiId: API_ID, apiHash: API_HASH }, phone);
      const partialSession = client.session.save();
      await client.disconnect();
      return res.json({ success: true, phoneCodeHash: result.phoneCodeHash, partialSession });
    }

    if (action === 'verify-code') {
      const { phone, code, phoneCodeHash, partialSession } = body;
      if (!phone||!code||!phoneCodeHash||!partialSession) return res.status(400).json({ error: 'Missing fields' });
      const client = await makeClient(partialSession);
      try {
        await client.invoke(new Api.auth.SignIn({ phoneNumber:phone, phoneCodeHash, phoneCode:code.trim() }));
        const session = client.session.save(); await client.disconnect();
        return res.json({ success: true, session });
      } catch (err) {
        if (err.errorMessage === 'SESSION_PASSWORD_NEEDED') { const ps2fa = client.session.save(); await client.disconnect(); return res.json({ success:false, need2FA:true, partialSession2FA:ps2fa }); }
        if (err.errorMessage === 'PHONE_CODE_EXPIRED') return res.json({ success:false, error:'OTP মেয়াদ শেষ! আবার পাঠাও।' });
        if (err.errorMessage === 'PHONE_CODE_INVALID') return res.json({ success:false, error:'OTP ভুল!' });
        throw err;
      }
    }

    if (action === 'verify-2fa') {
      const { password, partialSession2FA } = body;
      const client = await makeClient(partialSession2FA);
      const { computeCheck } = require('telegram/Password');
      const pwdInfo = await client.invoke(new Api.account.GetPassword());
      const check   = await computeCheck(pwdInfo, password);
      await client.invoke(new Api.auth.CheckPassword({ password: check }));
      const session = client.session.save(); await client.disconnect();
      return res.json({ success: true, session });
    }

    if (action === 'groups') {
      const client = await getAuthedClient();
      const dialogs = await client.getDialogs({ limit: 200 });
      const groups = dialogs.filter(d=>d.isGroup||d.isChannel).map(d=>({ id:d.id.toString(), title:d.title||'Unnamed', type:d.isChannel?'channel':'group', unread:d.unreadCount||0, username:d.entity?.username||null, members:d.entity?.participantsCount||0 }));
      await client.disconnect();
      return res.json({ success: true, groups });
    }

    // ── ALL DIALOGS FOR TG MANAGER ────────────────────────────
    if (action === 'all-dialogs') {
      const client = await getAuthedClient();
      const dialogs = await client.getDialogs({ limit: 200 });
      const all = dialogs.map(d => {
        const e = d.entity;
        let title = d.title || '';
        if (!title && e) title = [e.firstName, e.lastName].filter(Boolean).join(' ') || e.username || 'Unknown';
        return {
          id:       d.id.toString(),
          title:    title || 'Unknown',
          type:     d.isChannel ? 'channel' : d.isGroup ? 'group' : 'user',
          unread:   d.unreadCount || 0,
          username: e?.username || null,
          members:  e?.participantsCount || 0,
        };
      });
      await client.disconnect();
      return res.json({ success: true, dialogs: all });
    }

    // ── GET MESSAGES (preview) ────────────────────────────────
    if (action === 'get-messages') {
      const { dialogId, limit: lim = 30 } = body;
      if (!dialogId) return res.status(400).json({ error: 'Dialog ID দাও' });
      const client = await getAuthedClient();
      const entity = await client.getEntity(dialogId);
      const msgs   = await client.getMessages(entity, { limit: Math.min(parseInt(lim), 50) });
      const result = msgs.reverse().map(m => ({
        id:       m.id,
        text:     m.text || m.message || '',
        date:     m.date,
        fromName: m.sender ? ([m.sender.firstName, m.sender.lastName].filter(Boolean).join(' ') || m.sender.username || 'Unknown') : (m.post ? entity.title : 'Unknown'),
        fromUser: m.sender?.username || null,
        isMe:     m.out || false,
        media:    m.media ? m.media.className.replace('MessageMedia','') : null,
      }));
      await client.disconnect();
      return res.json({ success: true, messages: result, title: entity.title || entity.firstName || 'Chat' });
    }

    // ── SEND SINGLE MESSAGE ───────────────────────────────────
    if (action === 'send-message') {
      const { dialogId, message } = body;
      if (!dialogId || !message) return res.status(400).json({ error: 'Dialog ID আর message দাও' });
      const client = await getAuthedClient();
      const entity = await client.getEntity(dialogId);
      await client.sendMessage(entity, { message: message.trim() });
      await client.disconnect();
      return res.json({ success: true });
    }

    // ── MULTI GROUP MSG ───────────────────────────────────────
    if (action === 'send-group-msg') {
      const { groupIds, message } = body;
      if (!groupIds?.length) return res.status(400).json({ error: 'Group select করোনি' });
      if (!message?.trim())  return res.status(400).json({ error: 'Message লিখো' });
      const client = await getAuthedClient();
      const results = [];
      for (const gid of groupIds) {
        try {
          const entity = await client.getEntity(gid);
          await client.sendMessage(entity, { message: message.trim() });
          results.push({ id:gid, success:true });
          await new Promise(r => setTimeout(r, 800));
        } catch(e) { results.push({ id:gid, success:false, error:e.message }); }
      }
      await client.disconnect();
      return res.json({ success:true, sent:results.filter(r=>r.success).length, failed:results.filter(r=>!r.success).length, results });
    }

    // ── SEND DM ───────────────────────────────────────────────
    if (action === 'send-dm') {
      const { usernames, message } = body;
      if (!usernames?.length) return res.status(400).json({ error: 'User select করোনি' });
      if (!message?.trim())   return res.status(400).json({ error: 'Message লিখো' });
      const client = await getAuthedClient();
      const results = [];
      for (const uname of usernames) {
        try {
          await client.sendMessage(uname.replace('@',''), { message: message.trim() });
          results.push({ username:uname, success:true });
          await new Promise(r => setTimeout(r, 1000));
        } catch(e) { results.push({ username:uname, success:false, error:e.message }); }
      }
      await client.disconnect();
      return res.json({ success:true, sent:results.filter(r=>r.success).length, failed:results.filter(r=>!r.success).length, results });
    }

    // ── COLLECT MEMBERS ───────────────────────────────────────
    if (action === 'members') {
      const { groupId, days=7, minMessages=1, maxScan=500 } = body;
      if (!groupId) return res.status(400).json({ error: 'Group ID দাও' });
      const client = await getAuthedClient();
      const cutoff = Math.floor((Date.now() - parseInt(days)*86400000) / 1000);
      const entity = await client.getEntity(groupId);
      const memberMap = {};
      let offsetId=0, fetched=0, done=false;
      const scanLim = Math.min(parseInt(maxScan), 500);
      while (!done && fetched < scanLim) {
        const msgs = await client.getMessages(entity, { limit:100, offsetId: offsetId||undefined });
        if (!msgs?.length) break;
        for (const msg of msgs) {
          if (msg.date < cutoff) { done=true; break; }
          const s = msg.sender;
          if (!s||s.bot||!s.username) continue;
          const k = s.username.toLowerCase();
          if (!memberMap[k]) memberMap[k] = { username:s.username, firstName:s.firstName||'', messageCount:0 };
          memberMap[k].messageCount++;
        }
        offsetId = msgs[msgs.length-1].id;
        fetched += msgs.length;
        if (msgs.length < 100) break;
      }
      let members = Object.values(memberMap).filter(m=>m.messageCount>=parseInt(minMessages)).sort((a,b)=>b.messageCount-a.messageCount);
      await client.disconnect();
      return res.json({ success:true, members, total:members.length, scanned:fetched, groupTitle:entity.title });
    }

    // ── BULK CREATE GROUPS ────────────────────────────────────
    if (action === 'bulk-create-groups') {
      const { groups } = body;
      if (!groups?.length) return res.status(400).json({ error: 'Group list দাও' });
      const client = await getAuthedClient();
      const results = [];
      for (const g of groups) {
        try {
          const isChannel = g.type === 'channel';
          const created = await client.invoke(new Api.channels.CreateChannel({
            title:     g.title.trim(),
            about:     g.description || '',
            broadcast: isChannel,
            megagroup: !isChannel,
          }));
          const entity = created.chats?.[0];
          results.push({ title:g.title, success:true, id:entity?.id?.toString()||null });
          await new Promise(r => setTimeout(r, 1500));
        } catch(e) {
          results.push({ title:g.title, success:false, error:e.message });
        }
      }
      await client.disconnect();
      return res.json({ success:true, created:results.filter(r=>r.success).length, failed:results.filter(r=>!r.success).length, results });
    }

    return res.status(400).json({ error: 'Invalid action: ' + action });

  } catch (err) {
    console.error('[ERROR]', action, err.message);
    return res.status(500).json({ error: err.message || 'Server error' });
  }
};
