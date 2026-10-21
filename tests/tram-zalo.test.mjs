// Kiểm trạm chuyển tiếp Zalo OA bằng payload giả lập ĐÚNG mẫu tài liệu chính thức (sự kiện user_send_text).
// Chạy: npm install && npm test. Không gọi mạng thật.
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import handler, { kiemChuKy, dongGoi, chuyenTiep, docTuyen, dinhTuyen, laLenh } from '../api/zalo.js';

let dat = 0, hong = 0;
const check = (ten, thuc, mong) => {
  const ok = JSON.stringify(thuc) === JSON.stringify(mong);
  ok ? dat++ : hong++;
  console.log((ok ? '  ✓ ' : '  ✗ ') + ten + (ok ? '' : '  thực=' + JSON.stringify(thuc) + ' mong=' + JSON.stringify(mong)));
};

const env = { ZALO_OA_SECRET_KEY: 'oa-secret-thu', ZALO_OA_ID: '388613280878808645', GAS_URL: 'https://script.google.com/macros/s/THU/exec', ZALO_RELAY_SECRET: 'khoa-chung-thu' };
// Mẫu tài liệu chính thức, đổi nội dung sang tiếng Việt có dấu + emoji để kiểm mã hoá.
const ev = { app_id: '360846524940903967', sender: { id: '246845883529197922' }, user_id_by_app: '552177279717587730',
  recipient: { id: '388613280878808645' }, event_name: 'user_send_text',
  message: { text: '@Duyen Hong em soạn CV nhé 😀', msg_id: '96d3cdf3af150460909' }, timestamp: '154390853474' };
const raw = Buffer.from(JSON.stringify(ev, null, 1), 'utf8');      // cố ý khác JSON.stringify gọn: thân thô ≠ JSON viết lại
const mac = d => crypto.createHash('sha256').update(ev.app_id + d + ev.timestamp + env.ZALO_OA_SECRET_KEY, 'utf8').digest('hex');

console.log('Chữ ký Zalo');
check('Đúng công thức trên thân thô', kiemChuKy(raw, ev, mac(raw.toString('utf8')), env), { ok: true, ten: 'than-tho' });
check('Header có tiền tố mac=', kiemChuKy(raw, ev, 'mac=' + mac(raw.toString('utf8')), env).ok, true);
check('Đúng công thức trên JSON viết lại', kiemChuKy(raw, ev, mac(JSON.stringify(ev)), env), { ok: true, ten: 'json-viet-lai' });
check('Sai khoá ⇒ từ chối', kiemChuKy(raw, ev, crypto.createHash('sha256').update(ev.app_id + raw + ev.timestamp + 'khoa-gia').digest('hex'), env).ok, false);
check('Thiếu header ⇒ từ chối', kiemChuKy(raw, ev, undefined, env).ok, false);
check('Chưa đặt khoá ⇒ từ chối tất', kiemChuKy(raw, ev, mac(raw.toString('utf8')), {}).ok, false);
const sua = Buffer.from(raw.toString('utf8').replace('soạn', 'xoá'));
check('Sửa nội dung giữa đường ⇒ từ chối', kiemChuKy(sua, JSON.parse(sua), mac(raw.toString('utf8')), env).ok, false);

console.log('Gói sang Apps Script');
const g = JSON.parse(dongGoi(raw, env.ZALO_RELAY_SECRET, 1700000000000));
check('b64 giải ra đúng thân thô (tiếng Việt + emoji)', Buffer.from(g.b64, 'base64').equals(raw), true);
check('sig = HMAC(ts.b64)', g.sig, crypto.createHmac('sha256', env.ZALO_RELAY_SECRET).update('1700000000000.' + g.b64).digest('hex'));

console.log('Chuyển tiếp');
let goi = [];
const fetch302 = async (url, o) => { goi.push({ url, o }); return { status: 302 }; };
const T1 = { ten: 'mot', url: env.GAS_URL, khoa: env.ZALO_RELAY_SECRET };
check('302 của Apps Script = đã nhận', await chuyenTiep(raw, T1, fetch302, async () => {}), true);
check('Gọi đúng ?zalo=1, không theo chuyển hướng', [goi[0].url, goi[0].o.redirect], [env.GAS_URL + '?zalo=1', 'manual']);
goi = [];
let lan = 0;
const fetchLoi = async (url, o) => { goi.push(1); if (++lan < 3) throw new Error('mạng'); return { status: 200 }; };
check('Lỗi mạng ⇒ thử lại, lần 3 được', [await chuyenTiep(raw, T1, fetchLoi, async () => {}), goi.length], [true, 3]);
check('Hỏng cả 3 lần ⇒ false', await chuyenTiep(raw, T1, async () => ({ status: 500 }), async () => {}), false);

console.log('Định tuyến nhiều Flow (nhóm GMF, 21/10)');
const OA = env.ZALO_OA_ID;
const tuyenEnv = { ZALO_OA_ID: OA, ZALO_TUYEN: JSON.stringify([
  { ten: 'A', url: 'https://a/exec', khoa: 'kA', nhom: ['GA'], macDinh: true },
  { ten: 'B', url: 'https://b/exec', khoa: 'kB', nhom: ['GB'] }]) };
const T = docTuyen(tuyenEnv).tuyen;
const ten = ds => ds.map(t => t.ten);
const nhomEv = (gid, text, o) => Object.assign({ event_name: 'user_send_group_text', sender: { id: 'u1' }, recipient: { id: gid }, oa_id: OA,
  message: { text, message_id: 'x' } }, o || {});
const motMot = text => ({ event_name: 'user_send_text', sender: { id: 'u1' }, recipient: { id: OA }, message: { text, msg_id: 'y' } });
check('Tin nhóm A ⇒ chỉ Flow A', ten(dinhTuyen(nhomEv('GA', '[@1] soạn CV'), T, tuyenEnv)), ['A']);
check('Tin nhóm B ⇒ chỉ Flow B', ten(dinhTuyen(nhomEv('GB', '[@1] soạn CV'), T, tuyenEnv)), ['B']);
check('Nhóm không khai ⇒ không Flow nào (nội dung không rời trạm)', ten(dinhTuyen(nhomEv('GX', 'abc'), T, tuyenEnv)), []);
check('Nhóm của OA khác ⇒ bỏ', ten(dinhTuyen(nhomEv('GA', 'abc', { oa_id: 'OA-KHAC' }), T, tuyenEnv)), []);
check('oa_send_group_text ⇒ bỏ', ten(dinhTuyen(nhomEv('GA', 'abc', { event_name: 'oa_send_group_text' }), T, tuyenEnv)), []);
check('Vào/rời nhóm ⇒ bỏ', ten(dinhTuyen({ event_name: 'user_join_group', group_id: 'GA', users: [{ id: 'u1' }], message: {} }, T, tuyenEnv)), []);
check('1–1 lệnh (HUỶ mã / OK / số / MÃ) ⇒ mọi Flow', [motMot('Huỷ T-12'), motMot('ok'), motMot('2'), motMot('Mã')].map(e => ten(dinhTuyen(e, T, tuyenEnv))),
  [['A', 'B'], ['A', 'B'], ['A', 'B'], ['A', 'B']]);
check('1–1 tin thường ⇒ chỉ Flow mặc định (không lộ sang phòng khác)', ten(dinhTuyen(motMot('@Duyen Hong em soạn CV nhé'), T, tuyenEnv)), ['A']);
check('laLenh không nhận câu dài', [laLenh('ok em'), laLenh('Huỷ việc kia đi'), laLenh('123')], [false, false, false]);
check('Cấu hình sai bị từ chối', [
  docTuyen({ ZALO_TUYEN: JSON.stringify([{ url: 'u', khoa: 'k', nhom: [] }]) }).loi,
  docTuyen({ ZALO_TUYEN: JSON.stringify([{ url: 'u', khoa: 'k', macDinh: true }, { url: 'v', khoa: 'k2', macDinh: true }]) }).loi,
  docTuyen({ ZALO_TUYEN: JSON.stringify([{ url: 'u', khoa: 'k', nhom: ['G'], macDinh: true }, { url: 'v', khoa: 'k2', nhom: ['G'] }]) }).loi,
  docTuyen({ ZALO_TUYEN: JSON.stringify([{ url: 'u', nhom: [], macDinh: true }]) }).loi,
  docTuyen({ ZALO_TUYEN: '{khong json' }).loi],
  ['phải có đúng một tuyến macDinh', 'phải có đúng một tuyến macDinh', 'một nhóm khai ở hai tuyến', 'tuyến thiếu url hoặc khoa', 'ZALO_TUYEN không phải JSON']);
check('Cách cũ GAS_URL + ZALO_RELAY_SECRET vẫn chạy', docTuyen(env).tuyen.map(t => [t.url, t.khoa, t.macDinh]), [[env.GAS_URL, env.ZALO_RELAY_SECRET, true]]);
let goiTuyen = [];
const fT = async (url, o) => { goiTuyen.push({ url, sig: JSON.parse(o.body).sig, b64: JSON.parse(o.body).b64, ts: JSON.parse(o.body).ts }); return { status: 302 }; };
await Promise.all(T.map(t => chuyenTiep(raw, t, fT, async () => {})));
check('Mỗi Flow ký bằng khoá RIÊNG của mình', goiTuyen.map(g => g.sig === crypto.createHmac('sha256', g.url.indexOf('//a/') > -1 ? 'kA' : 'kB').update(g.ts + '.' + g.b64).digest('hex')), [true, true]);

console.log('Handler');
const goiHandler = async (body, headers, method = 'POST', e = env) => {
  const req = Readable.from([body]); req.method = method; req.headers = headers;
  const res = { statusCode: 0, body: '', end(s) { this.body = s; } };
  const t0 = Date.now();
  await handler(req, res, e);
  return [res.statusCode, res.body, Date.now() - t0 < 500];
};
check('POST hợp lệ ⇒ 200 ngay', await goiHandler(raw, { 'x-zevent-signature': mac(raw.toString('utf8')) }, 'POST', Object.assign({}, env, { GAS_URL: '' })), [200, 'ok', true]);
check('Sai chữ ký vẫn 200 (không để Zalo coi webhook hỏng)', await goiHandler(raw, { 'x-zevent-signature': 'abc' }), [200, 'ok', true]);
check('Thân rác ⇒ 200', await goiHandler(Buffer.from('không phải json'), {}), [200, 'ok', true]);
check('GET ⇒ 200', await goiHandler(Buffer.alloc(0), {}, 'GET'), [200, 'ok', true]);

console.log('\nTrạm Zalo: ' + dat + '/' + (dat + hong) + ' đạt');
process.exit(hong ? 1 : 0);
