// Trạm chuyển tiếp webhook Zalo OA → Flow (Apps Script). 09/10/2026; định tuyến nhóm GMF nhiều Flow 21/10/2026.
//
// Vì sao có trạm này (tài liệu chính thức developers.zalo.me, mục Webhook):
//  · Zalo đòi phản hồi HTTP 200 trong tối đa 2 giây; quá nhiều lần ⇒ webhook bị vô hiệu hoá. Apps Script trả 302 cho
//    POST và khởi động nguội thường quá 2 giây ⇒ trạm trả 200 NGAY, phần chuyển tiếp chạy sau (waitUntil).
//  · Webhook phải là domain https; script.google.com không xác thực domain được, flow-khqs.vercel.app thì được.
//
// Trạm KHÔNG giữ trạng thái, KHÔNG giữ token OA, KHÔNG lưu nội dung tin. Chống trùng làm ở Apps Script (msg_id).
//
// Biến môi trường (Vercel → Settings → Environment Variables), không bao giờ đưa vào repo (repo công khai):
//   ZALO_OA_SECRET_KEY  khoá bí mật dùng ký webhook (OAsecretKey trong công thức chữ ký)
//   ZALO_APP_ID         id ứng dụng (không bắt buộc — mặc định lấy app_id trong sự kiện)
//   ZALO_OA_ID          id OA; sự kiện của OA khác bị bỏ
//   ZALO_TUYEN          JSON mảng, mỗi bản Flow một dòng: [{"ten":"KHQS","url":"<GAS /exec>","khoa":"<khoá HMAC RIÊNG của Flow này>",
//                       "nhom":["<group_id>"],"macDinh":true}]. Đúng MỘT dòng macDinh (nhận tin 1–1 không phải lệnh) — sai thì trạm bỏ hết.
//   GAS_URL + ZALO_RELAY_SECRET  cách cũ (một Flow, chưa có nhóm): chỉ đọc khi không có ZALO_TUYEN.
//   ZALO_LOG_CHU_KY=1   (tạm, khi nối OA thật lần đầu) ghi chữ ký nhận/kỳ vọng ra log, KHÔNG ghi nội dung tin
import crypto from 'node:crypto';
import { waitUntil } from '@vercel/functions';

async function docThanTho(req) {
  const parts = [];
  for await (const c of req) parts.push(typeof c === 'string' ? Buffer.from(c) : c);
  return Buffer.concat(parts);
}

function bangNhau(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Công thức chính thức: mac = sha256(appId + data + timeStamp + OAsecretKey), "data là chuỗi json". Tài liệu không nói
// rõ data là thân thô hay JSON viết lại, header có tiền tố "mac=" không ⇒ chấp nhận cả hai dạng data và cả hai dạng
// header. Mọi biến thể đều đòi khoá bí mật nên không nới lỏng an toàn.
export function kiemChuKy(raw, ev, header, env) {
  const khoa = env.ZALO_OA_SECRET_KEY;
  if (!khoa || !header || !ev) return { ok: false, ly: 'thiếu khoá hoặc header' };
  const nhan = String(header).trim().replace(/^mac\s*=\s*/i, '').toLowerCase();
  const appId = env.ZALO_APP_ID || String(ev.app_id || '');
  const ts = String(ev.timestamp || '');
  const ung = [['than-tho', raw.toString('utf8')], ['json-viet-lai', JSON.stringify(ev)]];
  for (const [ten, data] of ung) {
    const mac = crypto.createHash('sha256').update(appId + data + ts + khoa, 'utf8').digest('hex');
    if (bangNhau(mac, nhan)) return { ok: true, ten };
  }
  if (env.ZALO_LOG_CHU_KY === '1') {
    console.log('chu-ky-khong-khop', JSON.stringify({ nhan, kyVong: ung.map(([ten, d]) => [ten, crypto.createHash('sha256').update(appId + d + ts + khoa, 'utf8').digest('hex')]) }));
  }
  return { ok: false, ly: 'sai chữ ký' };
}

// Bảng tuyến. Mỗi Flow một khoá HMAC riêng: quản trị viên Flow này không giả được gói vào Flow khác (người vào được Vercel
// vẫn đọc được mọi khoá — rủi ro đã ghi nhận, hội đồng 21/10).
export function docTuyen(env) {
  let ds;
  if (env.ZALO_TUYEN) {
    try { ds = JSON.parse(env.ZALO_TUYEN); } catch (e) { return { loi: 'ZALO_TUYEN không phải JSON' }; }
    if (!Array.isArray(ds) || !ds.length) return { loi: 'ZALO_TUYEN rỗng' };
    ds = ds.map(t => ({ ten: String(t.ten || ''), url: String(t.url || ''), khoa: String(t.khoa || ''),
      nhom: Array.isArray(t.nhom) ? t.nhom.map(String) : [], macDinh: t.macDinh === true }));
  } else if (env.GAS_URL && env.ZALO_RELAY_SECRET) {
    ds = [{ ten: 'mac-dinh', url: env.GAS_URL, khoa: env.ZALO_RELAY_SECRET, nhom: [], macDinh: true }];
  } else return { loi: 'chưa cấu hình tuyến' };
  if (ds.some(t => !t.url || !t.khoa)) return { loi: 'tuyến thiếu url hoặc khoa' };
  if (ds.filter(t => t.macDinh).length !== 1) return { loi: 'phải có đúng một tuyến macDinh' };
  const nhom = ds.flatMap(t => t.nhom);
  if (new Set(nhom).size !== nhom.length) return { loi: 'một nhóm khai ở hai tuyến' };
  return { tuyen: ds };
}

// Lệnh 1–1 (cùng cú pháp zaloDocLenh_ + zaloLaXinMa_ ở Apps Script): HUỶ [mã], OK, số, MÃ.
export function laLenh(text) {
  const t = String(text || '').trim().normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/đ/g, 'd').replace(/\s+/g, ' ');
  return /^(huy( s?t-[a-z0-9]+)?|ok|oke|okay|dong y|tao|\d{1,2}|ma|ma zalo)[.!?]*$/.test(t);
}

// Sự kiện ⇒ các tuyến nhận. Nhóm: đúng Flow khai nhóm đó (không khai ⇒ nội dung không rời Vercel). 1–1: lệnh tới MỌI Flow
// (mỗi Flow chỉ xử lý câu hỏi/việc của chính nó), tin khác chỉ tới Flow macDinh — nội dung không lọt sang Flow phòng khác
// (hội đồng 21/10). Mọi sự kiện khác (oa_send_group_*, ảnh, tệp, vào/rời nhóm...) bỏ.
export function dinhTuyen(ev, tuyen, env) {
  if (!ev || !ev.message) return [];
  if (ev.event_name === 'user_send_group_text') {
    if (env.ZALO_OA_ID && String(ev.oa_id) !== String(env.ZALO_OA_ID)) return [];
    const gid = String(ev.recipient && ev.recipient.id || '');
    return tuyen.filter(t => t.nhom.indexOf(gid) > -1);
  }
  if (ev.event_name === 'user_send_text') {
    if (env.ZALO_OA_ID && String(ev.recipient && ev.recipient.id) !== String(env.ZALO_OA_ID)) return [];
    return laLenh(ev.message.text) ? tuyen : tuyen.filter(t => t.macDinh);
  }
  return [];
}

export function dongGoi(raw, khoaChung, ts) {
  const b64 = raw.toString('base64');
  const sig = crypto.createHmac('sha256', khoaChung).update(String(ts) + '.' + b64).digest('hex');
  return JSON.stringify({ ts, b64, sig });
}

export async function chuyenTiep(raw, tuyen1, fetchFn = fetch, ngu = ms => new Promise(r => setTimeout(r, ms))) {
  const url = tuyen1.url + (tuyen1.url.indexOf('?') > -1 ? '&' : '?') + 'zalo=1';
  const cho = [0, 2000, 6000];
  for (let i = 0; i < cho.length; i++) {
    if (cho[i]) await ngu(cho[i]);
    try {
      // Apps Script chạy xong doPost rồi mới trả 302 sang trang kết quả ⇒ 302 = đã nhận. Không đi theo chuyển hướng.
      const r = await fetchFn(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: dongGoi(raw, tuyen1.khoa, Date.now()), redirect: 'manual' });
      if (r.status === 200 || r.status === 302) return true;
      console.error('chuyen-tiep-loi', tuyen1.ten, i + 1, r.status);
    } catch (e) {
      console.error('chuyen-tiep-loi', tuyen1.ten, i + 1, String(e && e.message || e));
    }
  }
  console.error('chuyen-tiep-that-bai-sau-3-lan', tuyen1.ten);   // Zalo đã nhận 200, không gửi lại ⇒ người giao sẽ không thấy OA trả lời
  return false;
}

export default async function handler(req, res, env = process.env, fetchFn = fetch) {
  if (req.method !== 'POST') { res.statusCode = 200; res.end('ok'); return; }
  let raw = Buffer.alloc(0), ev = null;
  try { raw = await docThanTho(req); ev = JSON.parse(raw.toString('utf8')); } catch (e) { ev = null; }
  const ck = kiemChuKy(raw, ev, req.headers['x-zevent-signature'], env);
  if (!ck.ok) console.warn('bo-su-kien', ck.ly);
  else {
    const bt = docTuyen(env);
    if (bt.loi) console.error('cau-hinh-tuyen-loi', bt.loi);
    else {
      const ds = dinhTuyen(ev, bt.tuyen, env);
      if (ds.length) waitUntil(Promise.all(ds.map(t => chuyenTiep(raw, t, fetchFn))));
    }
  }
  // Luôn 200 (kể cả sai chữ ký): trả lỗi cho Zalo chỉ khiến Zalo coi webhook hỏng; kẻ giả mạo cũng không biết gì thêm.
  res.statusCode = 200;
  res.end('ok');
}
