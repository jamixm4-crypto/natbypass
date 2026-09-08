module.exports = async ({ github, context }) => {
  const targetBetaTag = 'v1.9.225-beta3';
  const targetStableTag = 'v1.9.223';
  const keepTags = new Set([targetBetaTag, targetStableTag]);

  const betaChangelog = `## NatBypass v1.9.225-beta3

### 🛡️ Устойчивость ShadowTLS к активному зондированию ТСПУ (Active Probing Resistance)
- **Защита от активных зондов ТСПУ**: При получении неаутентифицированного ClientHello сервер больше не сбрасывает соединение через TCP RST (сигнатура прокси), а прозрачно проксирует запрос на реальный SNI-хост (\`gateway.icloud.com:443\`), возвращая сканеру легитимные сертификаты и TLS-ответы Apple/Cloudflare. При HTTP-запросах отдается стандартный код \`HTTP 400 Bad Request\`.
- **Строгая TLS 1.3 State Machine**: Введена строгая изоляция передачи прикладных данных (\`0x17\`), исключающая отправку Application Data до полного завершения стандартного рукопожатия (\`0x16\`).

### 🔐 Криптография и KDF-цепочка (Double Ratchet для UDP)
- **Устойчивость к потерям и нарушению порядка UDP-пакетов**: В заголовок зашифрованного пакета добавлен 4-байтный порядковый номер сообщения \`uint32\` и окно восстановления пропущенных ключей (skip-list до 64 сообщений). Потеря или перестановка UDP-пакетов больше не рассинхронизирует сессию.
- **CSPRNG Fail-Fast**: Устранены предсказуемые фолбэки на базе \`time.Now().UnixNano()\`. При исчерпании системной энтропии программа немедленно завершается с ошибкой (fail-fast), исключая появление уязвимых сессионных параметров.

### 🌐 Сеть, релеи и обфускация (резервный транспорт)
- **WSS Relay Race Condition**: Устранена паника при конкурентном отключении клиента во время пересылки пакета благодаря потокобезопасной сессии \`clientSession\` с атомарным жизненным циклом.
- **AmneziaWG anti-TSPU**: Усилены параметры пресета (\`Jc = 5\`, \`Jmin = 40\`, \`Jmax = 120\`, \`S1 = 56\`, \`S2 = 100\`) и внедрен автоматический MTU \`1280\` для ликвидации стандартной сигнатуры WireGuard MTU (1420).

### 🖥️ Локальная утилита диагностики
- **Диагностика**: Включена поддержка Windows Virtual Terminal, высококонтрастная цветовая палитра и улучшенная навигация по меню.`;

  console.log('--- STEP 1: Updating release notes and deleting old releases ---');
  try {
    const { data: releases } = await github.rest.repos.listReleases({
      owner: context.repo.owner,
      repo: context.repo.repo,
      per_page: 100,
    });
    console.log(`Found ${releases.length} releases`);

    for (const r of releases) {
      if (r.tag_name === targetBetaTag) {
        console.log(`Updating release notes and title for ${r.tag_name}...`);
        try {
          await github.rest.repos.updateRelease({
            owner: context.repo.owner,
            repo: context.repo.repo,
            release_id: r.id,
            name: `NatBypass ${targetBetaTag}`,
            body: betaChangelog,
            prerelease: true,
          });
          console.log(`✓ Updated release notes for ${r.tag_name}`);
        } catch (e) {
          console.error(`Failed to update release ${r.tag_name}: ${e.message}`);
        }
        continue;
      }

      if (r.tag_name === targetStableTag) {
        console.log(`Keeping STABLE release: ${r.tag_name} (ID: ${r.id})`);
        continue;
      }

      console.log(`Deleting superseded release: ${r.tag_name} (ID: ${r.id})`);
      try {
        await github.rest.repos.deleteRelease({
          owner: context.repo.owner,
          repo: context.repo.repo,
          release_id: r.id,
        });
        console.log(`✓ Deleted release ${r.tag_name}`);
      } catch (e) {
        console.error(`Failed to delete release ${r.tag_name}: ${e.message}`);
      }
    }
  } catch (err) {
    console.error(`Error in Step 1: ${err.message}`);
  }

  console.log('--- STEP 2: Deleting obsolete git tags ---');
  try {
    const { data: tags } = await github.rest.repos.listTags({
      owner: context.repo.owner,
      repo: context.repo.repo,
      per_page: 100,
    });
    console.log(`Found ${tags.length} tags on remote`);

    for (const t of tags) {
      if (keepTags.has(t.name)) {
        console.log(`Keeping tag: ${t.name}`);
        continue;
      }
      console.log(`Deleting remote tag: ${t.name}`);
      try {
        await github.rest.git.deleteRef({
          owner: context.repo.owner,
          repo: context.repo.repo,
          ref: `tags/${t.name}`,
        });
        console.log(`✓ Deleted tag ${t.name}`);
      } catch (e) {
        console.error(`Failed to delete tag ${t.name}: ${e.message}`);
      }
    }
  } catch (err) {
    console.error(`Error in Step 2: ${err.message}`);
  }

  console.log('--- STEP 3: Purging old completed workflow runs ---');
  let deletedCount = 0;
  for (let page = 1; page <= 5; page++) {
    let runs;
    try {
      const res = await github.rest.actions.listWorkflowRunsForRepo({
        owner: context.repo.owner,
        repo: context.repo.repo,
        per_page: 100,
        page: page,
      });
      runs = res.data.workflow_runs;
    } catch (err) {
      console.error(`Error listing runs on page ${page}: ${err.message}`);
      break;
    }

    if (!runs || runs.length === 0) break;

    for (const run of runs) {
      if (run.id === context.runId) continue;
      if (run.status === 'in_progress' || run.status === 'queued') continue;
      if (run.head_branch === targetBetaTag && run.conclusion === 'success' && run.name === 'Build, Sign and Release') {
        console.log(`Preserving release build for ${targetBetaTag}: ${run.name} (${run.id})`);
        continue;
      }

      try {
        await github.rest.actions.deleteWorkflowRun({
          owner: context.repo.owner,
          repo: context.repo.repo,
          run_id: run.id,
        });
        deletedCount++;
      } catch (e) {
        // ignore
      }
    }
  }
  console.log(`Successfully deleted ${deletedCount} old workflow runs.`);
};
