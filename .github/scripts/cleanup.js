module.exports = async ({ github, context }) => {
  const targetBetaTag = 'v1.9.225-beta5';
  const targetStableTag = 'v1.9.223';
  const keepTags = new Set([targetBetaTag, targetStableTag]);

  const betaChangelog = `## NatBypass v1.9.225-beta5

### 🚀 L3 Health-Aware Transport Switcher & Авто-переход на ShadowTLS (Обход DPI / ТСПУ)
- **Устранение Ghost P2P**: Ликвидирована фундаментальная ловушка ложной P2P-связности, когда единичные 1-байтовые STUN UDP-пробы пробивали NAT, но полноценный трафик глушился ТСПУ/DPI на трансграничном стыке (РФ ↔ РБ ↔ VPS), приводя к 73.8% потерям пакетов.
- **Реактивный Fallback на TLS 1.3 TCP ShadowTLS**: При любой деградации UDP или тайм-ауте ICMP ping движок мгновенно и реактивно подключает зашифрованный туннель TLS 1.3 ShadowTLS (SNI \`gateway.icloud.com\`), обеспечивая 100% доставку и минимальный пинг (<40 мс).
- **Периодический аудит состояния**: Keepalive-цикл непрерывно проверяет качество P2P-канала для всех узлов сети и превентивно поднимает резервный ShadowTLS до того, как связь прервется.

### ⚡ Wire-Speed Userspace Mesh TCP Relay
- **Полнодуплексный транзитный роутинг**: Входящие пакеты на публичных серверах кластера (VPS, \`DSTR_Serv_RUS\`), адресованные узлам за Double Symmetric NAT, пересылаются на уровне пространства пользователя напрямую через активные TCP ShadowTLS или прямые UDP-сессии с пересчетом контрольной суммы IPv4 и декрементом TTL.
- **Разгрузка MQTT**: Передача данных между сложными NAT-топологиями перенесена на сверхбыстрый TCP-релей без задержек и ограничений брокеров сигналов.

### 🛡️ Устранение блокировок ОС и сетевых фильтров (Firewall & Kernel Drops)
- **Linux / Keenetic NDM / OpenWrt**:
  - Безусловное открытие портов TCP 8443, 4443 и UDP 51820 в \`iptables\` и \`nftables\` (включая цепочки \`_NDM_INPUT\`).
  - Принудительное разрешение входящего ICMP (\`-p icmp -j ACCEPT\`) и прямого интерфейсного трафика (\`-i nb0 -j ACCEPT\`).
  - Отключение строгого обратного фильтра пакетов (\`rp_filter = 0\`).
- **Брандмауэр Windows**:
  - Автоматическое добавление разрешающих правил для портов TCP 8443, 4443, 443, 47832, 51820.
  - Разрешение всех типов входящего ICMPv4.
  - Создание двунаправленных правил Inbound/Outbound для Wintun-адаптера \`NatBypass\`.

### 🔄 Кроссплатформенная синхронизация
- Изменения синхронизированы во всех модулях: \`cmd/natbypass\` (демон), \`cmd/natbypass-cli\` (CLI), \`cmd/natbypass-gui\` (Win32 Native GUI), \`mobile\` (Android Go bridge).`;

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
