defmodule CA.HW do
  @moduledoc """
  Карта апаратного забезпечення ЦСК ЕРП (Hardware Inventory).
  Платформа: 5HT Technology Tristellar / Quadstellar на Intel Sapphire Rapids.
  Найвищий клас захищеності: TPM 2.0, Secure Boot, Intel TDX, FIPS 140-3.
  """

  def inventory do
    %{
      servers: [
        %{
          id: "HW-SRV-01",
          name: "Фізичні сервери (5HT Tristellar / Quadstellar, Sapphire Rapids)",
          controls: ["PE", "CP", "CM"],
          instances: [
            %{
              id: "ERP-SRV-01",
              inventory_num: "ERP-2025-001",
              model: "5HT Technology Tristellar 3U",
              host: "erp-app-01",
              spec: "2× Intel Xeon Gold 6442Y Sapphire Rapids (32c/64t each), 512 GB DDR5 ECC, 4× NVMe Gen5 U.2 3.84 TB, 2× 25 GbE, TPM 2.0, Intel TDX, FIPS 140-3",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка A1)",
              status: "Active (ERP Application Server)"
            },
            %{
              id: "ERP-SRV-02",
              inventory_num: "ERP-2025-002",
              model: "5HT Technology Tristellar 3U",
              host: "erp-app-02",
              spec: "2× Intel Xeon Gold 6442Y Sapphire Rapids (32c/64t each), 512 GB DDR5 ECC, 4× NVMe Gen5 U.2 3.84 TB, 2× 25 GbE, TPM 2.0, Intel TDX, FIPS 140-3",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка A1)",
              status: "Active (ERP Application Server — HA pair)"
            },
            %{
              id: "ERP-SRV-03",
              inventory_num: "ERP-2025-003",
              model: "5HT Technology Quadstellar 4U",
              host: "erp-db-primary",
              spec: "4× Intel Xeon Gold 6454S Sapphire Rapids (36c/72t each), 1 TB DDR5 ECC, 8× NVMe Gen5 U.2 7.68 TB RAID-10, 2× 100 GbE, Intel TDX, TPM 2.0, FIPS 140-3",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка A2)",
              status: "Active (Primary DB — PostgreSQL 17 TDE)"
            },
            %{
              id: "ERP-SRV-04",
              inventory_num: "ERP-2025-004",
              model: "5HT Technology Quadstellar 4U",
              host: "erp-db-replica",
              spec: "4× Intel Xeon Gold 6454S Sapphire Rapids (36c/72t each), 1 TB DDR5 ECC, 8× NVMe Gen5 U.2 7.68 TB RAID-10, 2× 100 GbE, Intel TDX, TPM 2.0, FIPS 140-3",
              year: 2025,
              location: "Львів (РЦОД ЕРП, стійка B1)",
              status: "Active (Replica DB — Streaming Replication)"
            },
            %{
              id: "ERP-SRV-05",
              inventory_num: "ERP-2025-005",
              model: "5HT Technology Tristellar 3U",
              host: "erp-sign-01",
              spec: "2× Intel Xeon Gold 6442Y Sapphire Rapids, 256 GB DDR5 ECC, 2× NVMe Gen5, ІІТ Гряда-301 HSM (PCIe), TPM 2.0, FIPS 140-3 Level 3",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка A3 — air-filtered)",
              status: "Active (Signing Server + HSM ІІТ Гряда)"
            },
            %{
              id: "ERP-SRV-06",
              inventory_num: "ERP-2025-006",
              model: "5HT Technology Tristellar 3U",
              host: "erp-siem-01",
              spec: "2× Intel Xeon Gold 6442Y Sapphire Rapids, 384 GB DDR5 ECC, 6× NVMe Gen5 U.2 7.68 TB (Wazuh Indexer cluster), TPM 2.0, FIPS 140-3",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка A4)",
              status: "Active (SIEM / XDR Wazuh 4.9 Indexer)"
            },
            %{
              id: "ERP-SRV-07",
              inventory_num: "ERP-2025-007",
              model: "5HT Technology Tristellar 3U",
              host: "erp-hyp-01",
              spec: "2× Intel Xeon Gold 6442Y Sapphire Rapids, 768 GB DDR5 ECC, 4× NVMe Gen5 U.2, VMware ESXi 8.0 U3, Intel TDX vTPM, DISA STIG ESXi 8, TPM 2.0",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка A2)",
              status: "Active (Hypervisor — VMware ESXi 8 STIG)"
            },
            %{
              id: "ERP-SRV-08",
              inventory_num: "ERP-2025-008",
              model: "5HT Technology Tristellar 3U",
              host: "erp-hyp-02",
              spec: "2× Intel Xeon Gold 6442Y Sapphire Rapids, 768 GB DDR5 ECC, 4× NVMe Gen5 U.2, VMware ESXi 8.0 U3, Intel TDX vTPM, DISA STIG ESXi 8, TPM 2.0",
              year: 2025,
              location: "Львів (РЦОД ЕРП, стійка B2)",
              status: "Active (Hypervisor HA — VMware ESXi 8 STIG)"
            }
          ]
        },
        %{
          id: "HW-SRV-02",
          name: "Віртуальні машини / Гіпервізори",
          controls: ["SC", "CM", "SI"],
          instances: []
        }
      ],
      kzi: [
        %{
          id: "HW-KZI-01",
          name: "Апаратні криптомодулі (HSM / Гряда)",
          controls: ["PE", "MP", "SC", "IA"],
          instances: [
            %{
              id: "ERP-KZI-01",
              inventory_num: "ERP-KZI-2025-001",
              model: "ІІТ Гряда-301 PCIe HSM",
              host: "erp-sign-01 (PCIe slot)",
              spec: "ДСТУ 4145-2002, ДСТУ 7564, ДСТУ 7624, PKCS#11 v2.40, FIPS 140-3 Level 3, апаратна генерація ключів",
              year: 2025,
              location: "Київ (ЦСК ЕРП, erp-sign-01)",
              status: "Active (Root CA key storage)"
            },
            %{
              id: "ERP-KZI-02",
              inventory_num: "ERP-KZI-2025-002",
              model: "ІІТ Гряда-301 PCIe HSM",
              host: "erp-sign-01 (PCIe slot 2)",
              spec: "ДСТУ 4145-2002, ДСТУ 7564, ДСТУ 7624, PKCS#11 v2.40, FIPS 140-3 Level 3 — резервний модуль",
              year: 2025,
              location: "Київ (ЦСК ЕРП, erp-sign-01)",
              status: "Active (Subordinate CA key storage — backup HSM)"
            },
            %{
              id: "ERP-KZI-03",
              inventory_num: "ERP-KZI-2025-003",
              model: "Автор CryptoCard Smart-01 (е-Токен, Смарт-карта)",
              host: "АРМ адміністраторів / операторів ЦСК",
              spec: "ДСТУ 4145, ISO 7816, PKCS#15, SHA-256/512, RSA-2048/4096, ECC P-256/384, tamper-evident",
              year: 2025,
              location: "Київ / Львів (виданий персоналу)",
              status: "Active (Operator authentication tokens × 12 шт.)"
            }
          ]
        },
        %{
          id: "HW-KZI-02",
          name: "Захищені носії ключової інформації (е-Токени, Смарт-карти)",
          controls: ["MP", "PE", "IA"],
          instances: []
        }
      ],
      network: [
        %{
          id: "HW-NET-01",
          name: "Маршрутизатори та комутатори ядра",
          controls: ["SC", "CM", "PE"],
          instances: [
            %{
              id: "ERP-NET-01",
              inventory_num: "ERP-NET-2025-001",
              model: "Cisco Catalyst 9500-48Y4C",
              host: "erp-core-sw-01",
              spec: "48× 25G SFP28 + 4× 100G QSFP28, MACsec IEEE 802.1AE, FIPS 140-2, Catalyst Center managed, DISA STIG IOS-XE",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка core)",
              status: "Active (Core Switch — MACsec шифрування)"
            },
            %{
              id: "ERP-NET-02",
              inventory_num: "ERP-NET-2025-002",
              model: "Cisco Catalyst 9500-48Y4C",
              host: "erp-core-sw-02",
              spec: "48× 25G SFP28 + 4× 100G QSFP28, MACsec IEEE 802.1AE, FIPS 140-2, VSS HA pair з erp-core-sw-01",
              year: 2025,
              location: "Львів (РЦОД ЕРП, стійка core)",
              status: "Active (Core Switch HA — VSS pair)"
            },
            %{
              id: "ERP-NET-03",
              inventory_num: "ERP-NET-2025-003",
              model: "Cisco ASR 1002-HX Router",
              host: "erp-border-gw-01",
              spec: "BGP AS Private, IPSec IKEv2, DSTU-криптографія через КЗІ ІІТ, DISA STIG IOS-XE, Hardware Crypto Engine",
              year: 2025,
              location: "Київ (ЦСК ЕРП, DMZ)",
              status: "Active (Border Gateway — BGP + IPSec VPN)"
            }
          ]
        },
        %{
          id: "HW-NET-02",
          name: "Міжмережеві екрани (Firewalls, IDS/IPS)",
          controls: ["SC", "AU", "CM"],
          instances: [
            %{
              id: "ERP-FW-01",
              inventory_num: "ERP-NET-2025-004",
              model: "Cisco Firepower 4145 NGFW (FTD 7.6)",
              host: "erp-fw-01",
              spec: "80 Gbps FW throughput, TLS 1.3 inspection, IPS, URL filtering, Cisco Secure Malware Analytics, DISA STIG FTD, FIPS 140-2",
              year: 2025,
              location: "Київ (ЦСК ЕРП, DMZ → Internal)",
              status: "Active (Primary NGFW — HA Active/Standby)"
            },
            %{
              id: "ERP-FW-02",
              inventory_num: "ERP-NET-2025-005",
              model: "Cisco Firepower 4145 NGFW (FTD 7.6)",
              host: "erp-fw-02",
              spec: "80 Gbps FW throughput, TLS 1.3 inspection, IPS — резервний у парі HA з erp-fw-01",
              year: 2025,
              location: "Київ (ЦСК ЕРП, DMZ → Internal)",
              status: "Active (Standby NGFW — HA pair)"
            }
          ]
        }
      ],
      endpoints: [
        %{
          id: "HW-END-01",
          name: "Робочі станції операторів / адміністраторів",
          controls: ["PE", "AC", "SI"],
          instances: [
            %{
              id: "ERP-WS-01",
              inventory_num: "ERP-WS-2025-001",
              model: "5HT Technology Workstation Compact (Sapphire Rapids)",
              host: "erp-admin-ws-01",
              spec: "Intel Core Ultra 9 285K (Arrow Lake), 128 GB DDR5, 2 TB NVMe Gen5, TPM 2.0, Intel vPro, Windows 11 Pro 24H2 DISA STIG, BitLocker XTS-AES-256, Microsoft Pluton",
              year: 2025,
              location: "Київ (ЦСК ЕРП, захищений кабінет адміністраторів)",
              status: "Active (Administrator Workstation — NATO UC APL)"
            },
            %{
              id: "ERP-WS-02",
              inventory_num: "ERP-WS-2025-002",
              model: "5HT Technology Workstation Compact (Sapphire Rapids)",
              host: "erp-op-ws-01",
              spec: "Intel Core Ultra 9 285K, 64 GB DDR5, 1 TB NVMe Gen5, TPM 2.0, UA Linux 24.04 ДСТУ-hardened, LUKS2 AES-256, FreeIPA enrolled, ІІТ КЗІ смарт-карта",
              year: 2025,
              location: "Київ (ЦСК ЕРП, операційний зал)",
              status: "Active (Operator Workstation — ДСТУ hardened)"
            }
          ]
        },
        %{
          id: "HW-END-02",
          name: "Мобільні пристрої",
          controls: ["AC", "SC", "MP"],
          instances: []
        }
      ],
      storage: [
        %{
          id: "HW-STG-01",
          name: "Системи зберігання даних (СЗД, SAN, NAS)",
          controls: ["PE", "MP", "CP"],
          instances: [
            %{
              id: "ERP-STG-01",
              inventory_num: "ERP-STG-2025-001",
              model: "5HT Technology AllFlash NVMe Array (Sapphire Rapids Storage Controller)",
              host: "erp-san-01",
              spec: "24× NVMe Gen5 U.2 15.36 TB = 368 TB raw, AES-256-XTS Self-Encrypting Drives (SED FIPS 140-3), NVMe-oF TCP/RDMA, 4× 100 GbE, inline dedup+compress",
              year: 2025,
              location: "Київ (ЦСК ЕРП, стійка storage A)",
              status: "Active (Primary All-Flash SAN — шифрований)"
            },
            %{
              id: "ERP-STG-02",
              inventory_num: "ERP-STG-2025-002",
              model: "5HT Technology AllFlash NVMe Array",
              host: "erp-san-02",
              spec: "24× NVMe Gen5 U.2 15.36 TB = 368 TB raw, AES-256-XTS SED FIPS 140-3, NVMe-oF TCP, async replication до Львова",
              year: 2025,
              location: "Львів (РЦОД ЕРП, стійка storage B)",
              status: "Active (Replica All-Flash SAN — async DR)"
            }
          ]
        },
        %{
          id: "HW-STG-02",
          name: "Стрічкові бібліотеки (Tape Libraries) для офлайн-бекапів",
          controls: ["PE", "MP"],
          instances: [
            %{
              id: "ERP-TAPE-01",
              inventory_num: "ERP-STG-2025-003",
              model: "HPE StoreEver MSL3040 Tape Library",
              host: "erp-tape-01",
              spec: "40 LTO-9 слотів × 18 TB = 720 TB native / 1.8 PB compressed, AES-256 tape encryption, offline rotation, фізичний журнал видачі касет",
              year: 2025,
              location: "Київ (ЦСК ЕРП, окрема кімната стрічок — air-gapped)",
              status: "Active (Offline Tape Backup — air-gapped, Veeam + Bacula)"
            }
          ]
        }
      ]
    }
  end
end
