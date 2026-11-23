// Public landing page of the sandbox bank (device port, "/"): what this is,
// where to get the app, the bank address to enter. Downloads (/download/*)
// come from SANDBOX_DOWNLOADS_DIR, filled by `sandbox/bin/sandbox publish-apk`.
import { createReadStream, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { escapeHtml as e, sendHtml } from './http.mjs';

export const APK_NAME = 'voxtel-demo.apk';

export function createPublicPages(config) {
  const b = config.bank.branding;

  function apk() {
    if (!config.downloadsDir) return null;
    const file = join(config.downloadsDir, APK_NAME);
    return existsSync(file) ? { file, size: statSync(file).size, updated: statSync(file).mtime } : null;
  }

  function landing(res) {
    const address = config.publicUrl ?? '(адрес порта устройств песочницы)';
    const android = apk();
    sendHtml(res, 200, `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(b.name)} · демо</title><style>
body{margin:0;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#14232f;background:linear-gradient(#e6f7f4,#f7fafa 320px)}
main{max-width:560px;margin:0 auto;padding:32px 20px 48px}.logo{width:64px;height:64px;border-radius:32px;background:${e(b.primaryColor)};color:#fff;display:grid;place-items:center;font-size:30px;font-weight:700}
h1{font-size:26px;margin:18px 0 4px}.card{background:#fff;border-radius:16px;padding:18px 20px;margin:16px 0;box-shadow:0 2px 10px rgba(30,90,90,.07)}
a.btn{display:block;text-align:center;background:${e(b.primaryColor)};color:#fff;text-decoration:none;font-weight:600;padding:14px;border-radius:14px;margin-top:12px}
code{background:#eef5f4;padding:2px 6px;border-radius:4px;font-size:15px;word-break:break-all}.note{color:#6a7b88;font-size:14px}ol{padding-left:20px}
</style></head><body><main><div class="logo">✓</div><h1>${e(b.name)}</h1><p class="note">${e(b.notice)}</p>
<div class="card"><b>iPhone</b>${config.testflightUrl
      ? `<ol><li>Установите приложение <b>TestFlight</b> из App Store.</li><li>Откройте приглашение и нажмите «Установить».</li></ol><a class="btn" href="${e(config.testflightUrl)}">Открыть в TestFlight</a>`
      : '<p class="note">Версия для iPhone появится здесь после публикации в TestFlight.</p>'}</div>
<div class="card"><b>Android</b>${android
      ? `<ol><li>Скачайте файл и откройте его.</li><li>Разрешите установку из этого источника, если телефон спросит.</li></ol><a class="btn" href="/download/${APK_NAME}">Скачать APK (${(android.size / 1048576).toFixed(1)} МБ)</a>
<p class="note">Обновлено ${e(android.updated.toISOString().slice(0, 10))}.</p>`
      : '<p class="note">Файл для Android появится здесь после публикации.</p>'}</div>
<div class="card"><b>Вход</b><ol><li>В приложении на экране входа нажмите «Адрес банка» и укажите<br><code>${e(address)}</code></li>
<li>Войдите логином и паролем, которые вам выдал банк.</li><li>Нажмите «Подключить телефон»: ключ подтверждения создаётся в защищённом хранилище телефона.</li></ol></div>
<p class="note">Операции подтверждаются NEXUS-SIGN. Все средства тестовые, реальных платежей нет.</p></main></body></html>`);
  }

  function download(res, name) {
    const file = name === APK_NAME ? apk() : null;
    if (!file) return false;
    res.writeHead(200, {
      'Content-Type': 'application/vnd.android.package-archive',
      'Content-Length': file.size,
      'Content-Disposition': `attachment; filename="${APK_NAME}"`,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-cache',
    });
    createReadStream(file.file).pipe(res);
    return true;
  }

  return { landing, download };
}
