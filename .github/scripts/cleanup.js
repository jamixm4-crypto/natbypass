module.exports = async ({ github, context }) => {
  const targetBetaTag = 'v1.9.225-beta4';
  const targetStableTag = 'v1.9.223';
  const keepTags = new Set([targetBetaTag, targetStableTag]);

  const betaChangelog = `## NatBypass v1.9.225-beta4

### 🛡️ Настоящий TLS 1.3 RFC 8446 в ShadowTLS (Обход DPI / ТСПУ)
- **Устранение сигнатуры Fake TLS**: Полностью ликвидирована псевдо-TLS обертка с ручной записью 0x17. Все TCP-сессии ShadowTLS теперь используют полноценный стэк \`crypto/tls\` со стандартным рукопожатием TLS 1.3 (ClientHello → ServerHello → EncryptedExtensions → Certificate → CertificateVerify → Finished) и динамическим рандомизированным паддингом (16–48 байт).
- **Стойкость к активному зондированию ТСПУ**: При несовпадении сетевого ключа или получении нелегитимных запросов соединение прозрачно проксируется на реальный SNI-хост (\`gateway.icloud.com:443\`), не выдавая присутствие туннеля.
- **Разрешение коллизий Simultaneous Open**: Детерминированное согласование ролей (клиент/сервер) на основе сравнения 32-байтных nonce \`clientRandom\`, исключающее блокировки при одновременном TCP Hole Punching.
- **Оптимизация для роутеров (MIPS/ARM)**: Кеширование mTLS-сертификатов узла в памяти предотвращает повторную генерацию ключей ECDSA и разгружает CPU.

### 🔐 Криптография: Stateless HKDF и CSPRNG Hardening
- **Stateless HKDF на каждый UDP-пакет**: Переход от хрупкой последовательной цепочки KDF к независимому выводу сессионного ключа \`deriveMsgKeyStateless(rootKey, counter)\` через HKDF-Expand. Потеря или перестановка UDP-пакетов в ненадежных трансграничных сетях больше не приводит к потере синхронизации.
- **Защита от атак повторного воспроизведения**: Реализован 64-битный скользящий фильтр анти-реплея по RFC 2401.
- **CSPRNG Fail-Fast**: Полностью удалены небезопасные резервные генераторы на базе системного времени. При сбое системной энтропии приложение немедленно аварийно завершается (fail-fast).

### 🌐 Сеть, релеи и стабильность
- **WSS Relay Deadlock / Race Fix**: Потокобезопасная очистка сессий WebSocket Relay при отключении клиентов, устраняющая гонки и утечки ресурсов.
- **AmneziaWG anti-TSPU**: Пресет обфускации (\`Jc = 5\`, \`Jmin = 40\`, \`Jmax = 120\`, \`S1 = 56\`, \`S2 = 100\`) с автоматическим MTU 1280.
- **Диагностика**: Локальная инженерная консоль NatBypass-Diag с поддержкой Windows VT100 и высококонтрастным интерфейсом.`;

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
        console.log(`Updating release notes, publishing for ${r.tag_name}...`);
        try {
          await github.rest.repos.updateRelease({
            owner: context.repo.owner,
            repo: context.repo.repo,
            release_id: r.id,
            name: `NatBypass ${targetBetaTag}`,
            body: betaChangelog,
            prerelease: true,
            draft: false,
          });
          console.log(`✓ Updated and published release notes for ${r.tag_name}`);
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
