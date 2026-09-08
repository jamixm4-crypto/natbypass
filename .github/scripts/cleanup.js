module.exports = async ({ github, context }) => {
  const targetBetaTag = 'v1.9.225-beta2';
  const targetStableTag = 'v1.9.223';
  const keepTags = new Set([targetBetaTag, targetStableTag]);

  const betaChangelog = `## NatBypass v1.9.225-beta2

### 🛡️ Исправления надежности автообновления и перезапуска служб (OTA)
- **Linux (systemctl / systemd)**: Устранено аварийное прерывание службы при OTA-обновлении. Переход на асинхронный вызов \`systemctl --no-block restart natbypass\` напрямую через PID 1. Это гарантирует, что systemd не уничтожит процесс рестарта при выходе родительского демона из control-group.
- **Keenetic (MarNet / Entware) и OpenWrt (BusyBox ash)**: В фоновый скрипт перезапуска \`/opt/etc/init.d/S99natbypass restart\` добавлены ловушки сигналов \`trap '' HUP INT TERM\`, предотвращающие сброс службы при выходе родительского процесса.

### 🌐 P2P Mesh & NAT Traversal
- **Мгновенный сброс таймаутов пробива**: При изменении внешнего STUN-адреса узла или восстановлении связи счетчик проб \`ProbeCount\` сбрасывается в \`0\`, а таймер \`probeBackoff\` очищается. Прямое P2P-соединение восстанавливается сразу, без ожидания 5-минутного таймаута.
- **Отказоустойчивость**: Улучшена координация между прямыми P2P UDP-каналами и сигнальным транспортом. AmneziaWG и зашифрованный Relay задействуются как автоматический резервный канал при блокировке чистого P2P/UDP.

### 🔐 Криптография и безопасность
- **Стандартизация KDF-цепочки**: Реализована симметричная KDF-цепочка на базе RFC 5869 HKDF-SHA256 с гарантией Perfect Forward Secrecy (PFS) для защиты сессионных ключей.
- **Mesh mTLS**: Срок действия mTLS-сертификатов узлов mesh-сети сокращен с 10 лет до 1 года (365 дней).
- **WSS Anti-Replay**: Окно допустимого рассинхрона временных меток \`X-Auth-Timestamp\` сокращено с 10 минут до 45 секунд для защиты от атак повторного воспроизведения.
- **CSPRNG-аудит**: Устранены unchecked-вызовы чтения энтропии в ShadowTLS и WireGuard, добавлены строгие проверки \`io.ReadFull(rand.Reader)\` с безопасным фолбэком.

### 📦 Защита от блокировок и обфускация (резервный транспорт)
- Тонкая настройка параметров обфускации резервного транспорта AmneziaWG 3.1 под противодействие ТСПУ (\`Jc = 5\`, рандомизация мусорных пакетов 40–120 байт).`;

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
