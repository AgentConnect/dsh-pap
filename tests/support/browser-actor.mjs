import { chromium } from 'playwright';
import { AcceptanceError } from './config.mjs';

/** Operate only the actual authenticated product UI; never call management RPCs. */
export async function withUserBrowser(runtime, run) {
  let browser;
  let stage = 'launch';
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1440, height: 1000 } });
    const web = await runtime.rpc('browser');
    stage = 'login';
    // The URL is a local login credential. Keep it out of navigation failures and logs.
    try {
      const response = await context.request.get(web.authenticatedUrl);
      if (!response.ok()) throw new Error('Login failed');
    } catch { throw new AcceptanceError('acceptance_browser_login_failed'); }
    const page = await context.newPage();
    stage = 'navigation';
    await page.goto(web.origin, { waitUntil: 'load', timeout: 30000 });
    const actor = {
      page,
      async openIdentities() {
        stage = 'preview_notice';
        const notice = page.getByRole('dialog').filter({ has: page.getByRole('heading', { name: '预览版说明', exact: true }) });
        try { await notice.waitFor({ state: 'visible', timeout: 5000 }); }
        catch (error) { if (error.name !== 'TimeoutError') throw error; }
        if (await notice.isVisible()) await notice.getByRole('button', { name: '继续', exact: true }).click();
        stage = 'account_menu';
        await page.getByRole('button', { name: '账号菜单', exact: true, includeHidden: true }).click();
        await page.getByRole('menuitem', { name: '设置', exact: true }).click();
        stage = 'identity_settings';
        const dialog = page.getByRole('dialog', { name: '设置', exact: true });
        await dialog.getByRole('button', { name: '身份管理', exact: true }).click();
        await page.getByRole('heading', { name: '身份管理', exact: true }).waitFor();
        stage = 'scenario';
      },
      async enterPhone(phone) {
        stage = 'factor_entry';
        if (!phone.startsWith('+86')) throw new AcceptanceError('acceptance_browser_dialing_code_required');
        try { await page.getByLabel('注册手机号', { exact: true }).fill(phone.slice(3)); }
        catch { throw new AcceptanceError('acceptance_browser_factor_entry_failed'); }
      },
      async enterOtp(code) {
        try { await page.getByLabel('短信验证码', { exact: true }).fill(code); }
        catch { throw new AcceptanceError('acceptance_browser_factor_entry_failed'); }
        await page.getByRole('button', { name: '验证并注册', exact: true }).click();
      },
      async openProtocols() {
        await this.openIdentities();
        await page.getByRole('dialog', { name: '设置', exact: true }).getByRole('button', { name: '协议管理', exact: true }).click();
        await page.getByRole('heading', { name: '协议管理', exact: true }).waitFor();
      },
      async openPapConnections() {
        await this.openIdentities();
        stage = 'pap_settings_navigation';
        await page.getByRole('dialog', { name: '设置', exact: true }).getByRole('button', { name: 'PAP 连接', exact: true }).click();
        await page.getByRole('heading', { name: 'PAP 连接', exact: true }).waitFor();
        stage = 'pap_settings_refresh';
        await page.getByRole('button', { name: '刷新连接状态', exact: true }).click();
        await page.locator('button:not([disabled])').filter({hasText:/^刷新连接状态$/u}).waitFor();
        stage = 'pap_connection_action';
      },
      async setReadMode(mode) {
        await page.getByLabel('读取模式', { exact: true }).selectOption(mode);
        const save = page.getByRole('button', { name: '保存权限', exact: true });
        await save.click();
        const deadline = Date.now() + 10000;
        while (Date.now() < deadline && await save.isEnabled()) await new Promise(resolve => setTimeout(resolve, 100));
        if (await save.isEnabled()) throw new AcceptanceError('acceptance_protocol_policy_save_unconfirmed');
      },
    };
    stage = 'scenario';
    return await run(actor);
  } catch (error) {
    if (error instanceof AcceptanceError || error.name === 'AssertionError') throw error;
    throw new AcceptanceError('acceptance_browser_' + stage + '_failed');
  } finally { await browser?.close(); }
}
