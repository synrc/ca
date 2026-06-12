defmodule CA.Sys do
  @moduledoc """
  Карта систем і програмного забезпечення (Software Asset Taxonomy).
  Платформа: 5HT Technology Tristellar/Quadstellar на Intel Sapphire Rapids.
  ОС: UA Linux (ДСТУ-hardened), Windows 11 Pro (NATO STIG), ІІТ КЗІ.
  Уніфікована 2-рівнева структура: група -> :instances.
  """

  @doc """
  Перелік програмних активів, які вимагають специфічних контролів захисту.
  """
  def inventory do
    %{
      os: [
        %{
          id: "SYS-OS-01",
          name: "Серверні ОС (UA Linux ДСТУ-hardened)",
          controls: ["CM", "SI", "AC"],
          instances: [
            %{
              id: "SYS-OS-01-UAL",
              name: "UA Linux 24.04 LTS (ДСТУ-hardened, SELINUX Enforcing)",
              version: "24.04 LTS",
              platform: "5HT Tristellar (Intel Xeon Gold 6442Y Sapphire Rapids, 2×32c)",
              profile: "CIS Level 2 + ДСТУ 8754, FIPS 140-3 криптомодулі",
              status: "Production"
            },
            %{
              id: "SYS-OS-01-WIN",
              name: "Windows Server 2025 Datacenter (NATO STIG + DISA hardened)",
              version: "2025 Datacenter",
              platform: "5HT Quadstellar (Intel Xeon Gold 6454S Sapphire Rapids, 4×36c)",
              profile: "DISA STIG Windows Server 2025, NATO UC APL, CIS L2",
              status: "Production"
            },
            %{
              id: "SYS-OS-01-ESX",
              name: "VMware ESXi 8.0 Update 3 (vSphere Foundation)",
              version: "8.0 U3",
              platform: "5HT Quadstellar (Intel Xeon Gold 6454S Sapphire Rapids, 4×36c)",
              profile: "VMware Security Configuration Guide, DISA STIG ESXi 8",
              status: "Production (Hypervisor)"
            }
          ]
        },
        %{
          id: "SYS-OS-02",
          name: "Клієнтські ОС (Windows 11 Pro NATO STIG)",
          controls: ["CM", "SI", "AC"],
          instances: [
            %{
              id: "SYS-OS-02-W11",
              name: "Windows 11 Pro 24H2 (DISA STIG + Windows Defender Credential Guard)",
              version: "24H2 (Build 26100)",
              platform: "Робочі станції операторів / адміністраторів",
              profile: "DISA STIG WN11, NATO UC APL, CIS Benchmark L2, BitLocker XTS-AES-256",
              status: "Active"
            },
            %{
              id: "SYS-OS-02-UAL",
              name: "UA Linux Desktop 24.04 LTS (ДСТУ, GNOME Hardened)",
              version: "24.04 LTS Desktop",
              platform: "АРМ операторів реєстрації ЦСК",
              profile: "ДСТУ 8754, AppArmor Enforcing, LUKS2 шифрування диску",
              status: "Active"
            }
          ]
        }
      ],
      db: [
        %{
          id: "SYS-DB-01",
          name: "Реляційні СУБД (PostgreSQL, Oracle)",
          controls: ["SC", "AC", "AU", "CP"],
          instances: [
            %{
              id: "SYS-DB-01-PG",
              name: "PostgreSQL 17.2 (TDE + pgAudit + pg_partman)",
              version: "17.2",
              platform: "5HT Tristellar (Sapphire Rapids, NVMe U.2 Gen5 RAID-10)",
              profile: "CIS PostgreSQL 17 Benchmark L2, Transparent Data Encryption (TDE), pgAudit",
              status: "Production (Primary)"
            },
            %{
              id: "SYS-DB-01-ORA",
              name: "Oracle Database 23ai (Advanced Security Option, TDE, Vault)",
              version: "23ai (23.5)",
              platform: "5HT Quadstellar (Sapphire Rapids, Oracle Exadata-compatible NVMe)",
              profile: "CIS Oracle 23 Benchmark, Oracle Advanced Security, Database Vault, Audit Vault",
              status: "Production"
            }
          ]
        },
        %{
          id: "SYS-DB-02",
          name: "NoSQL та кеші (Redis, etcd)",
          controls: ["SC", "AC", "AU"],
          instances: [
            %{
              id: "SYS-DB-02-RDS",
              name: "Redis 7.4 (TLS 1.3, ACL, persistence RDB+AOF)",
              version: "7.4",
              platform: "5HT Tristellar (Sapphire Rapids, in-memory tier)",
              profile: "Redis Security Hardening Guide, mTLS between nodes, ACL-based access",
              status: "Production (Session Cache)"
            }
          ]
        }
      ],
      middleware: [
        %{
          id: "SYS-MW-01",
          name: "Веб-сервери та балансувальники (Nginx, HAProxy)",
          controls: ["SC", "CM", "AU"],
          instances: [
            %{
              id: "SYS-MW-01-NGX",
              name: "Nginx 1.27 (TLS 1.3 only, OCSP Stapling, CT Logs, HSTS)",
              version: "1.27",
              platform: "5HT Tristellar (Sapphire Rapids, 25 GbE NIC)",
              profile: "Mozilla SSL Config Generator (Modern), CIS Nginx Benchmark, WAF ModSecurity 3",
              status: "Production (Reverse Proxy + WAF)"
            },
            %{
              id: "SYS-MW-01-HAP",
              name: "HAProxy 3.0 (HA pair, health checks, rate limiting)",
              version: "3.0 LTS",
              platform: "5HT Tristellar (Sapphire Rapids, активний кластер 2×)",
              profile: "HAProxy Security Hardening, mTLS backend, DDoS rate-limiting ACL",
              status: "Production (Load Balancer)"
            }
          ]
        },
        %{
          id: "SYS-MW-02",
          name: "Сервіси каталогів (Active Directory, FreeIPA)",
          controls: ["IA", "AC", "SC"],
          instances: [
            %{
              id: "SYS-MW-02-AD",
              name: "Active Directory Domain Services 2025 (LAPS v2, Protected Users, Tiering)",
              version: "Windows Server 2025 AD DS",
              platform: "5HT Quadstellar (Sapphire Rapids, резервний DC у другій стійці)",
              profile: "DISA STIG AD, Microsoft Tiering Model, LAPS v2, Credential Guard, AD Recycle Bin",
              status: "Production (Primary DC + Secondary DC)"
            },
            %{
              id: "SYS-MW-02-IPA",
              name: "FreeIPA 4.12 (Kerberos V, OTP, CA sub-ідентифікатор)",
              version: "4.12",
              platform: "5HT Tristellar (Sapphire Rapids, UA Linux 24.04)",
              profile: "CIS FreeIPA Hardening, SCIM provisioning, TOTP MFA, ДСТУ-сумісні сертифікати",
              status: "Production (Linux Identity)"
            }
          ]
        }
      ],
      app: [
        %{
          id: "SYS-APP-00",
          name: "Erlang/OTP та Elixir runtime",
          desc: "Платформа виконання для всіх сервісів ЦСК ЕРП. Fault-tolerant, distributed, hot-code-reload.",
          controls: ["SI", "SC", "CM", "CP"],
          instances: [
            %{
              id: "SYS-APP-00-ERL",
              name: "Erlang/OTP 27.3 (SMP, BEAM VM, distribution TLS)",
              version: "27.3",
              platform: "UA Linux 24.04 (erp-app-01, erp-app-02, erp-sign-01)",
              profile: "OTP release, distroless Docker (Podman rootless), inter-node TLS 1.3, epmd замінений на TLS dist, DISA STIG container hardening",
              status: "Active (Runtime — всі Elixir/Erlang сервіси ЦСК)"
            },
            %{
              id: "SYS-APP-00-ELX",
              name: "Elixir 1.18.3 (N2O, NITRO, FORM, Bandit)",
              version: "1.18.3",
              platform: "UA Linux 24.04 (erp-app-01, erp-app-02) — Tristellar Sapphire Rapids",
              profile: "N2O.DEV Framework, Bandit HTTP/2+WebSocket, OTP release, BEAM VM cluster 2 вузли",
              status: "Active (Web API + UI сервіси ЦСК ЕРП)"
            },
            %{
              id: "SYS-APP-00-EMQ",
              name: "EMQ X 2.12 (MQTT 5.0 / MQTT-SN, Erlang/OTP cluster)",
              version: "2.12",
              platform: "UA Linux 24.04 (erp-app-01, erp-app-02 — Tristellar Sapphire Rapids)",
              profile: "MQTT 5.0 + MQTT-SN, TLS 1.3 mutual auth, cluster mode (2 вузли), rule engine → ABAC/ACL",
              status: "Active (MQTT Broker — IoT / async події ЦСК ЕРП)"
            }
          ]
        },
        %{
          id: "SYS-APP-SYNRC",
          name: "Платформа: Системні продукти ERP/1",
          desc: "Системний фундамент платформи е-урядування (github.com/synrc, github.com/erpuno).",
          controls: ["AC", "AU", "SI", "SC", "CP", "IA"],
          instances: [
            %{
              id: "SYS-SYNRC-CA",
              name: "Сертифікати",
              version: "7.4",
              platform: "github.com/synrc/ca",
              profile: """
Центр сертифікації реєстраційних посвідчень і їх ABAC реквізитної атрибутики для інфраструктури PKI. X.509v3, PKCS#10 CSR, OCSP, CRL, ДСТУ 4145, ДСТУ 7564, EST (RFC 7030), ACME (RFC 8555), ІІТ Гряда-301 HSM backend.

Облікова система заходів безпеки (CMDB):
  NIST SP 800-53 Rev.5:
    CM-8   — System Component Inventory: веде точний реєстр всіх HW/SW/FW компонентів КСЗІ (hw.ex, sys.ex, net.ex).
    CM-8(1)— Inventory | Updates During Installs/Removals: зміни компонентів фіксуються в git-history synrc/ca.
    CM-8(2)— Inventory | Automated Maintenance: автоматичне оновлення інвентарю через CA.PRO API (cmdb_profiles.ex).
    CM-9   — Configuration Management Plan: план КМ зберігається у security/ репозиторії.
    PM-5   — System Inventory: перелік всіх ІТС організації (CA.PRO.categories/1, CA.PRO.inventory/1).
    PM-6   — Information Security Measures of Performance: метрики ефективності через CA.PRO.risk/1, CA.PRO.sys/1.
    CA-7   — Continuous Monitoring: безперервний моніторинг статусу всіх засобів захисту через SIEM (Wazuh).
    PL-2   — System Security and Privacy Plans: план безпеки формується на базі профілів в erpuno/*.ex.
    RA-2   — Security Categorization: категоризація даних реалізована в CA.Data (data.ex).
    RA-3   — Risk Assessment: таксономія ризиків в CA.Risk (risk.ex), CA.PRO.risk/1.
  НД ТЗІ:
    НД ТЗІ 3.7-003-2023 §4.2 — Облік об'єктів захисту: формуляр системи реалізований в erpuno/*.ex.
    НД ТЗІ 3.7-003-2023 §5   — Експлуатаційна документація: inventory_num поле у кожному HW-екземплярі.
    НД ТЗІ 1.6-005-22         — Вимоги до захисту: controls: [] поле у кожному профілі CMDB.
    НД ТЗІ 2.6-001-11         — Державна експертиза КСЗІ: audit trail через CA.PRO.categories/1 API.
""",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-VPN",
              name: "Тунелі",
              version: "1.0",
              platform: "github.com/erpuno/vpn",
              profile: "Високопродуктивна система побудови захищених децентралізованих тунелів (L2/L3) на базі віртуальної машини Erlang/OTP.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-LDAP",
              name: "Директорія",
              version: "1.0",
              platform: "github.com/erpuno/ldap",
              profile: "PKI-aware LDAP з підтримкою X.500.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-CHAT",
              name: "Комунікатор",
              version: "4.2",
              platform: "github.com/synrc/chat",
              profile: "TLS X.690 DER сервер v1+, v2 і v3 протоколів і ПК КЗІ X.509 v1 протоколу BUDDHA.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-BPMN",
              name: "Процеси",
              version: "6.11",
              platform: "github.com/synrc/bpe",
              profile: "Процесний BPMN рушій ISO 19510 для бізнес-логіки, який використовується в державних компаніях і має TLS X.690 DER інтерфейс.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-MQTT",
              name: "Брокер",
              version: "2.12",
              platform: "github.com/erpuno/mq",
              profile: "MQTT v5.0 сервер, який реалізує персистетні сабскріпшин топіки стандарту SO/IEC 20922:2016.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-KVS",
              name: "Сховище",
              version: "10.0",
              platform: "github.com/synrc/kvs",
              profile: "Бібліотека KVS яка реалізує SNIA інтерфейс для NVMe дисків оснований на ітераторах, сумісних з RocksDB та більш складними системами CEPH.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-WS",
              name: "Фреймворк",
              version: "11.0",
              platform: "github.com/synrc/n2o",
              profile: "N2O/NITRO фреймворк для розробки веб-додатків.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-FORM",
              name: "Форми",
              version: "1.3",
              platform: "github.com/synrc/form",
              profile: "Бібліотека X-FORM для відображення реквізитної інформації і автоматичної генерації клієнтських і серверних валідацій.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-ASN1",
              name: "Компілятор",
              version: "1.0",
              platform: "github.com/synrc/asn1",
              profile: "ASN.1 X.680 компілятор для мов програмування ANSI C99 і Apple Swift.",
              status: "Active"
            },
            %{
              id: "SYS-SYNRC-ABAC",
              name: "Контроль",
              version: "1.0",
              platform: "github.com/synrc/abac",
              profile: "Бібліотека ABAC для контролю доступу на рівні реквізитної інформації документів та їх сертифікатів.",
              status: "Active"
            }
          ]
        },
        %{
          id: "SYS-APP-ERP",
          name: "Продукти: Корпоративні системи ERP/1",
          desc: "Корпоративні та державні системи (github.com/erpuno).",
          controls: ["AC", "AU", "SI", "SC", "CP", "IA"],
          instances: [
            %{
              id: "SYS-ERP-EDU",
              name: "Освіта",
              version: "1.0",
              platform: "github.com/erpuno/edu",
              profile: "Автоматизована інформаційна система управління освітнім процесом ISO 21001, навчальною діяльністю та адмініструванням закладів освіти.",
              status: "Active"
            },
            %{
              id: "SYS-ERP-HEALTH",
              name: "Здоров'я",
              version: "1.0",
              platform: "github.com/erpuno/health",
              profile: "Медична інформаційна система HL7 для автоматизації обліку медичних послуг та управління медичною інформацією в електронному вигляді.",
              status: "Active"
            },
            %{
              id: "SYS-ERP-MAIL",
              name: "Документи",
              version: "1.0",
              platform: "github.com/erpuno/mail",
              profile: "Автоматизація роботи з електронними документами у вигляді CRM системи згідно інструкції з діловодства №40 від 2024 року.",
              status: "Active"
            },
            %{
              id: "SYS-ERP-ACC",
              name: "Облік",
              version: "1.0",
              platform: "github.com/erpuno/acc",
              profile: "Комплексна ERP система автоматизації бухгалтерського обліку, кадрового діловодства та розрахунку заробітної плати для підприємств і державних установ.",
              status: "Active"
            },
            %{
              id: "SYS-ERP-WAREHOUSE",
              name: "Склад",
              version: "1.0",
              platform: "github.com/erpuno/warehouse",
              profile: "Автоматизована система управління складським господарством та матеріально-технічним забезпеченням підприємств і державних установ.",
              status: "Active"
            },
            %{
              id: "SYS-ERP-CART",
              name: "Реєстри",
              version: "1.0",
              platform: "github.com/erpuno/cart",
              profile: "Універсальна платформа для створення, ведення та управління державними, відомчими та корпоративними інформаційними реєстрами будь-якого масштабу.",
              status: "Active"
            }
          ]
        },
        %{
          id: "SYS-APP-01",
          name: "Програмні комплекси ЦСК (ІІТ, Сайфер)",
          controls: ["SI", "SC", "AU", "CP"],
          instances: [
            %{
              id: "SYS-APP-01-IIT",
              name: "ІІТ Користувач ЦСК-1 (бібліотека «ІІТ Гряда-301»)",
              version: "3.0.1",
              platform: "UA Linux 24.04 + Windows 11 Pro (x64, ARM64)",
              profile: "Сертифіковано ДССЗІ України, ДСТУ 4145, ДСТУ 7564, ДСТУ 7624; NATO PKI interop",
              status: "Active (Primary KSP for digital signatures)"
            },
            %{
              id: "SYS-APP-01-CIP",
              name: "Сайфер HSM Middleware (PKCS#11 + CMS + TSP клієнт)",
              version: "2.8",
              platform: "UA Linux 24.04 + Windows Server 2025",
              profile: "Сертифіковано ДССЗІ, PKCS#11 v2.40, RFC 5652 CMS, RFC 3161 TSP, FIPS 140-3 Level 3",
              status: "Active (HSM interface)"
            },
            %{
              id: "SYS-APP-01-SIGN",
              name: "Автор Е-Підпис Сервер (batch signing, LTV, XAdES-BES)",
              version: "5.2",
              platform: "UA Linux 24.04 (Docker container, rootless Podman)",
              profile: "Сертифіковано ДССЗІ, ETSI EN 319 132 XAdES, PAdES, CAdES, LTV підписи",
              status: "Active (Document signing service)"
            }
          ]
        },
        %{
          id: "SYS-APP-02",
          name: "Системи моніторингу та логування (SIEM, Zabbix)",
          controls: ["AU", "IR"],
          instances: [
            %{
              id: "SYS-APP-02-WZ",
              name: "Wazuh 4.9 SIEM/XDR (OSSEC-based, FIM, compliance CIS/NIST)",
              version: "4.9",
              platform: "5HT Tristellar (Sapphire Rapids, dedicated indexer cluster)",
              profile: "NIST SP 800-92, PCI-DSS v4 log rules, ДСТУ 8943, агенти на всіх хостах",
              status: "Production (SIEM + HIDS)"
            },
            %{
              id: "SYS-APP-02-ZBX",
              name: "Zabbix 7.2 (active agents, encrypted PSK transport, alerting)",
              version: "7.2 LTS",
              platform: "5HT Tristellar (Sapphire Rapids, окрема monitoring VLAN)",
              profile: "CIS Zabbix Hardening, TLS/PSK агенти, HA pair proxy, alert escalation",
              status: "Production (Infrastructure Monitoring)"
            }
          ]
        }
      ],
      infrastructure: [
        %{
          id: "SYS-INF-01",
          name: "Системи резервного копіювання (Veeam, Bacula)",
          controls: ["CP", "CM", "SC", "AU"],
          instances: [
            %{
              id: "SYS-INF-01-VBR",
              name: "Veeam Backup & Replication 12.3 (immutable backups, SureBackup)",
              version: "12.3",
              platform: "5HT Quadstellar (Sapphire Rapids, Scale-Out Backup Repository + tape)",
              profile: "Veeam Hardened Repository (Linux immutable), 3-2-1-1-0 правило, AES-256 шифрування",
              status: "Production (Primary Backup)"
            },
            %{
              id: "SYS-INF-01-BCL",
              name: "Bacula Community 15.0 (offline tape + air-gapped archive)",
              version: "15.0",
              platform: "Окремий air-gapped сервер (без мережевого підключення)",
              profile: "Офлайн tape rotation, GnuPG шифрування архівів, фізичний журнал видачі касет",
              status: "Active (Air-gapped Offline Archive)"
            }
          ]
        }
      ]
    }
  end
end
