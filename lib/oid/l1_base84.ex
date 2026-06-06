defmodule CA.L1.Base84 do
  def groups do
    [
      {:category, "УПРАВЛІННЯ ДОСТУПОМ (AC)"},
      {
        "УПРАВЛІННЯ ОБЛІКОВИМИ ЗАПИСАМИ (AC-2)",
        [
        CA.SPE.oid(:"id-spe-ac-2"),
        CA.SPE.oid(:"id-spe-ac-2-5")
        ]
      },
      {
        "ЗАБЕЗПЕЧЕННЯ ДОСТУПУ (AC-3)",
        [
        CA.SPE.oid(:"id-spe-ac-3")
        ]
      },
      {
        "УПРАВЛІННЯ ІНФОРМАЦІЙНИМИ ПОТОКАМИ (AC-4)",
        [
        CA.SPE.oid(:"id-spe-ac-4")
        ]
      },
      {
        "РОЗМЕЖУВАННЯ ОБОВ'ЯЗКІВ (AC-5)",
        [
        CA.SPE.oid(:"id-spe-ac-5")
        ]
      },
      {
        "МІНІМІЗАЦІЯ ПОВНОВАЖЕНЬ (AC-6)",
        [
        CA.SPE.oid(:"id-spe-ac-6"),
        CA.SPE.oid(:"id-spe-ac-6-1"),
        CA.SPE.oid(:"id-spe-au-9-4")
        ]
      },
      {
        "НЕПРИВІЛЕЙОВАНИЙ ДОСТУП ДО НЕЗАХИЩЕНИХ ФУНКЦІЙ (AC-6(2)) (AC-6)",
        [
        CA.SPE.oid(:"id-spe-ac-6-2"),
        CA.SPE.oid(:"id-spe-ac-6-5")
        ]
      },
      {
        "ЗАБОРОНА НЕПРИВІЛЕЙОВАНИМ КОРИСТУВАЧАМ ВИКОНУВАТИ ПРИВІЛЕЙОВАНІ ФУНКЦІЇ (AC-6(10)) (AC-6)",
        [
        CA.SPE.oid(:"id-spe-ac-6-10")
        ]
      },
      {
        "НЕВДАЛІ СПРОБИ ВХОДУ В СИСТЕМУ (AC-7)",
        [
        CA.SPE.oid(:"id-spe-ac-7")
        ]
      },
      {
        "ПОПЕРЕДЖЕННЯ ПРО ВИКОРИСТАННЯ СИСТЕМИ (AC-8)",
        [
        CA.SPE.oid(:"id-spe-ac-8")
        ]
      },
      {
        "БЛОКУВАННЯ ПРИСТРОЮ (AC-11)",
        [
        CA.SPE.oid(:"id-spe-ac-11"),
        CA.SPE.oid(:"id-spe-ac-11-1")
        ]
      },
      {
        "ПРИПИНЕННЯ СЕАНСУ (AC-12)",
        [
        CA.SPE.oid(:"id-spe-ac-12")
        ]
      },
      {
        "ВІДДАЛЕНИЙ ДОСТУП (AC-17)",
        [
        CA.SPE.oid(:"id-spe-ac-17"),
        CA.SPE.oid(:"id-spe-ac-17-3"),
        CA.SPE.oid(:"id-spe-ac-17-4")
        ]
      },
      {
        "БЕЗДРОТОВИЙ ДОСТУП (AC-18)",
        [
        CA.SPE.oid(:"id-spe-ac-18")
        ]
      },
      {
        "КОНТРОЛЬ ДОСТУПУ ДЛЯ МОБІЛЬНИХ ПРИСТРОЇВ (AC-19)",
        [
        CA.SPE.oid(:"id-spe-ac-19"),
        CA.SPE.oid(:"id-spe-ac-19-5")
        ]
      },
      {
        "ВИКОРИСТАННЯ ЗОВНІШНІХ СИСТЕМ (AC-20)",
        [
        CA.SPE.oid(:"id-spe-ac-20"),
        CA.SPE.oid(:"id-spe-ac-20-1"),
        CA.SPE.oid(:"id-spe-ac-20-2")
        ]
      },
      {
        "ПУБЛІЧНО ДОСТУПНИЙ КОНТЕНТ (AC-22)",
        [
        CA.SPE.oid(:"id-spe-ac-22")
        ]
      },
      {:category, "ОБІЗНАНІСТЬ ТА НАВЧАННЯ (AT)"},
      {
        "НАВЧАННЯ З ПІДВИЩЕННЯ ОБІЗНАНОСТІ (AT-2)",
        [
        CA.SPE.oid(:"id-spe-at-2"),
        CA.SPE.oid(:"id-spe-at-2-2")
        ]
      },
      {
        "РОЛЬОВЕ НАВЧАННЯ (AT-3)",
        [
        CA.SPE.oid(:"id-spe-at-3")
        ]
      },
      {:category, "АУДИТ ТА ПІДЗВІТНІСТЬ (AU)"},
      {
        "ПОДІЇ АУДИТУ (AU-2)",
        [
        CA.SPE.oid(:"id-spe-au-2")
        ]
      },
      {
        "ЗМІСТ ЗАПИСІВ АУДИТУ (AU-3)",
        [
        CA.SPE.oid(:"id-spe-au-3"),
        CA.SPE.oid(:"id-spe-au-3-1")
        ]
      },
      {
        "ЗБЕРЕЖЕННЯ ЗАПИСІВ АУДИТУ (AU-11)",
        [
        CA.SPE.oid(:"id-spe-au-11"),
        CA.SPE.oid(:"id-spe-au-12")
        ]
      },
      {
        "РЕАГУВАННЯ НА ВІДМОВИ ОБРОБКИ ДАНИХ АУДИТУ (AU-5)",
        [
        CA.SPE.oid(:"id-spe-au-5")
        ]
      },
      {
        "ОГЛЯД, АНАЛІЗ І ЗВІТНІСТЬ АУДИТУ (AU-6)",
        [
        CA.SPE.oid(:"id-spe-au-6"),
        CA.SPE.oid(:"id-spe-au-6-3")
        ]
      },
      {
        "СКОРОЧЕННЯ ЗАПИСІВ АУДИТУ ТА ФОРМУВАННЯ ЗВІТУ (AU-7)",
        [
        CA.SPE.oid(:"id-spe-au-7")
        ]
      },
      {
        "ПОЗНАЧКА ЧАСУ (AU-8)",
        [
        CA.SPE.oid(:"id-spe-au-8")
        ]
      },
      {
        "ЗАХИСТ ІНФОРМАЦІЇ АУДИТУ (AU-9)",
        [
        CA.SPE.oid(:"id-spe-au-9"),
        CA.SPE.oid(:"id-spe-au-9-4")
        ]
      },
      {:category, "УПРАВЛІННЯ КОНФІГУРАЦІЄЮ (CM)"},
      {
        "БАЗОВА КОНФІГУРАЦІЯ (CM-2)",
        [
        CA.SPE.oid(:"id-spe-cm-2")
        ]
      },
      {
        "НАЛАШТУВАННЯ КОНФІГУРАЦІЇ (CM-6)",
        [
        CA.SPE.oid(:"id-spe-cm-6")
        ]
      },
      {
        "УПРАВЛІННЯ ЗМІНАМИ КОНФІГУРАЦІЇ (CM-3)",
        [
        CA.SPE.oid(:"id-spe-cm-3")
        ]
      },
      {
        "АНАЛІЗ ВПЛИВУ НА БЕЗПЕКУ ТА ПРИВАТНІСТЬ (CM-4)",
        [
        CA.SPE.oid(:"id-spe-cm-4")
        ]
      },
      {
        "ОБМЕЖЕННЯ ДОСТУПУ ДО ЗМІНИ (CM-5)",
        [
        CA.SPE.oid(:"id-spe-cm-5")
        ]
      },
      {
        "МІНІМАЛЬНО НЕОБХІДНА ФУНКЦІОНАЛЬНІСТЬ (CM-7)",
        [
        CA.SPE.oid(:"id-spe-cm-7"),
        CA.SPE.oid(:"id-spe-cm-7-1")
        ]
      },
      {:category, "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ (IA)"},
      {
        "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ КОРИСТУВАЧІВ (IA-2)",
        [
        CA.SPE.oid(:"id-spe-ia-2")
        ]
      },
      {
        "ІДЕНТИФІКАЦІЯ ТА АВТЕНТИФІКАЦІЯ ПРИСТРОЇВ (IA-3)",
        [
        CA.SPE.oid(:"id-spe-ia-3")
        ]
      },
      {
        "БАГАТОФАКТОРНА АВТЕНТИФІКАЦІЯ ПРИВІЛЕЙОВАНИХ ОБЛІКОВИХ ЗАПИСІВ (IA-2(1)) (IA-2)",
        [
        CA.SPE.oid(:"id-spe-ia-2-1"),
        CA.SPE.oid(:"id-spe-ia-2-2")
        ]
      },
      {
        "ДОСТУП ДО ОБЛІКОВИХ ЗАПИСІВ — СТІЙКІСТЬ ДО ВІДТВОРЕННЯ (IA-2(8)) (IA-2)",
        [
        CA.SPE.oid(:"id-spe-ia-2-8")
        ]
      },
      {
        "УПРАВЛІННЯ ІДЕНТИФІКАЦІЄЮ (IA-4)",
        [
        CA.SPE.oid(:"id-spe-ia-4")
        ]
      },
      {
        "АВТЕНТИФІКАЦІЯ НА ОСНОВІ ПАРОЛЯ (IA-5(1)) (IA-5)",
        [
        CA.SPE.oid(:"id-spe-ia-5-1")
        ]
      },
      {
        "ПРИХОВУВАННЯ ЗВОРОТНОГО ЗВ'ЯЗКУ АВТЕНТИФІКАТОРА (IA-6)",
        [
        CA.SPE.oid(:"id-spe-ia-6")
        ]
      },
      {
        "АВТЕНТИФІКАТОР УПРАВЛІННЯ (IA-5)",
        [
        CA.SPE.oid(:"id-spe-ia-5")
        ]
      },
      {:category, "РЕАГУВАННЯ НА ІНЦИДЕНТИ (IR)"},
      {
        "ОБРОБКА ІНЦИДЕНТУ (IR-4)",
        [
        CA.SPE.oid(:"id-spe-ir-4")
        ]
      },
      {
        "МОНІТОРИНГ ІНЦИДЕНТУ (IR-5)",
        [
        CA.SPE.oid(:"id-spe-ir-5"),
        CA.SPE.oid(:"id-spe-ir-6"),
        CA.SPE.oid(:"id-spe-ir-7")
        ]
      },
      {
        "ПЕРЕВІРКА РЕАГУВАНЬ НА ІНЦИДЕНТИ (IR-3)",
        [
        CA.SPE.oid(:"id-spe-ir-3")
        ]
      },
      {
        "НАВЧАННЯ З РЕАГУВАННЯ НА ІНЦИДЕНТИ (IR-2)",
        [
        CA.SPE.oid(:"id-spe-ir-2")
        ]
      },
      {
        "ПЛАН РЕАГУВАННЯ НА ІНЦИДЕНТИ (IR-8)",
        [
        CA.SPE.oid(:"id-spe-ir-8")
        ]
      },
      {:category, "ТЕХНІЧНЕ ОБСЛУГОВУВАННЯ (MA)"},
      {
        "ІНСТРУМЕНТИ ДЛЯ ОБСЛУГОВУВАННЯ (MA-3)",
        [
        CA.SPE.oid(:"id-spe-ma-3"),
        CA.SPE.oid(:"id-spe-ma-3-1"),
        CA.SPE.oid(:"id-spe-ma-3-2")
        ]
      },
      {
        "ВІДДАЛЕНЕ ОБСЛУГОВУВАННЯ (MA-4)",
        [
        CA.SPE.oid(:"id-spe-ma-4")
        ]
      },
      {
        "ТЕХНІЧНИЙ ПЕРСОНАЛ (MA-5)",
        [
        CA.SPE.oid(:"id-spe-ma-5")
        ]
      },
      {:category, "ЗАХИСТ НОСІЇВ ІНФОРМАЦІЇ (MP)"},
      {
        "ЗБЕРІГАННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-4)",
        [
        CA.SPE.oid(:"id-spe-mp-4")
        ]
      },
      {
        "ДОСТУП ДО НОСІЇВ ІНФОРМАЦІЇ (MP-2)",
        [
        CA.SPE.oid(:"id-spe-mp-2")
        ]
      },
      {
        "ЗНИЩЕННЯ ІНФОРМАЦІЇ НА НОСІЯХ ІНФОРМАЦІЇ (MP-6)",
        [
        CA.SPE.oid(:"id-spe-mp-6")
        ]
      },
      {
        "МАРКУВАННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-3)",
        [
        CA.SPE.oid(:"id-spe-mp-3")
        ]
      },
      {
        "ТРАНСПОРТУВАННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-5)",
        [
        CA.SPE.oid(:"id-spe-mp-5"),
        CA.SPE.oid(:"id-spe-sc-28")
        ]
      },
      {
        "ВИКОРИСТАННЯ НОСІЇВ ІНФОРМАЦІЇ (MP-7)",
        [
        CA.SPE.oid(:"id-spe-mp-7")
        ]
      },
      {:category, "ПЛАНУВАННЯ БЕЗПЕРЕРВНОЇ РОБОТИ (CP)"},
      {
        "РЕЗЕРВНЕ КОПІЮВАННЯ (CP-9)",
        [
        CA.SPE.oid(:"id-spe-cp-9")
        ]
      },
      {:category, "БЕЗПЕКА ПЕРСОНАЛУ (PS)"},
      {
        "ПЕРЕВІРКА ПЕРСОНАЛУ (PS-3)",
        [
        CA.SPE.oid(:"id-spe-ps-3")
        ]
      },
      {
        "ЗВІЛЬНЕННЯ ПЕРСОНАЛУ (PS-4)",
        [
        CA.SPE.oid(:"id-spe-ps-4"),
        CA.SPE.oid(:"id-spe-ps-5")
        ]
      },
      {:category, "ФІЗИЧНИЙ ЗАХИСТ ТА ЗАХИСТ НАВКОЛИШНЬОГО СЕРЕДОВИЩА (PE)"},
      {
        "РЕ-2 ДОСТУПУ (PE-2)",
        [
        CA.SPE.oid(:"id-spe-pe-2")
        ]
      },
      {
        "МОНІТОРИНГ ФІЗИЧНОГО ДОСТУПУ (PE-6)",
        [
        CA.SPE.oid(:"id-spe-pe-6")
        ]
      },
      {
        "АЛЬТЕРНАТИВНЕ РОБОЧЕ МІСЦЕ (PE-17)",
        [
        CA.SPE.oid(:"id-spe-pe-17")
        ]
      },
      {
        "ФІЗИЧНИЙ ДОСТУП ДО СИСТЕМИ (PE-3)",
        [
        CA.SPE.oid(:"id-spe-pe-3"),
        CA.SPE.oid(:"id-spe-pe-5")
        ]
      },
      {
        "РЕ-4 ЛІНІЙ ЕЛЕКТРОЖИВЛЕННЯ (PE-4)",
        [
        CA.SPE.oid(:"id-spe-pe-4")
        ]
      },
      {:category, "ОЦІНКА РИЗИКІВ (RA)"},
      {
        "ОЦІНЮВАННЯ РИЗИКУ (RA-3)",
        [
        CA.SPE.oid(:"id-spe-ra-3")
        ]
      },
      {
        "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ (RA-5)",
        [
        CA.SPE.oid(:"id-spe-ra-5")
        ]
      },
      {:category, "ОЦІНЮВАННЯ, АВТОРИЗАЦІЯ ТА МОНІТОРИНГ (CA)"},
      {
        "ОЦІНЮВАННЯ (CA-2)",
        [
        CA.SPE.oid(:"id-spe-ca-2")
        ]
      },
      {
        "ПЛАН УСУНЕННЯ НЕДОЛІКІВ ТА КОНТРОЛЬНІ ПОКАЗНИКИ (CA-5)",
        [
        CA.SPE.oid(:"id-spe-ca-5")
        ]
      },
      {
        "БЕЗПЕРЕРВНИЙ МОНІТОРИНГ (CA-7)",
        [
        CA.SPE.oid(:"id-spe-ca-7")
        ]
      },
      {
        "ВЗАЄМОДІЯ СИСТЕМ (CA-3)",
        [
        CA.SPE.oid(:"id-spe-ca-3")
        ]
      },
      {:category, "ЗАХИСТ СИСТЕМ ТА КОМУНІКАЦІЙ (SC)"},
      {
        "ДОСТУПНІСТЬ РЕСУРСІВ (SC-7)",
        [
        CA.SPE.oid(:"id-spe-sc-7")
        ]
      },
      {
        "ІНФОРМАЦІЯ В ЗАГАЛЬНИХ СИСТЕМНИХ РЕСУРСАХ (SC-4)",
        [
        CA.SPE.oid(:"id-spe-sc-4")
        ]
      },
      {
        "ВІДМОВА ЗА ЗАМОВЧУВАННЯМ - ДОЗВІЛ ЗА ВИНЯТКОМ (SC-7(5)) (SC-7)",
        [
        CA.SPE.oid(:"id-spe-sc-7-5")
        ]
      },
      {
        "КОНФІДЕНЦІЙНІСТЬ ТА ЦІЛІСНІСТЬ ПЕРЕДАЧІ (SC-8)",
        [
        CA.SPE.oid(:"id-spe-sc-8"),
        CA.SPE.oid(:"id-spe-sc-8-1"),
        CA.SPE.oid(:"id-spe-sc-28"),
        CA.SPE.oid(:"id-spe-sc-28-1")
        ]
      },
      {
        "ВІДКЛЮЧЕННЯ МЕРЕЖІ (SC-10)",
        [
        CA.SPE.oid(:"id-spe-sc-10")
        ]
      },
      {
        "ВСТАНОВЛЕННЯ КЛЮЧАМИ (SC-12)",
        [
        CA.SPE.oid(:"id-spe-sc-12")
        ]
      },
      {
        "КРИПТОГРАФІЧНИЙ ЗАХИСТ (SC-13)",
        [
        CA.SPE.oid(:"id-spe-sc-13")
        ]
      },
      {
        "СПІЛЬНІ ОБЧИСЛЮВАЛЬНІ ПРИСТРОЇ ТА ЗАСТОСУНКИ (SC-15)",
        [
        CA.SPE.oid(:"id-spe-sc-15")
        ]
      },
      {
        "МОБІЛЬНИЙ КОД (SC-18)",
        [
        CA.SPE.oid(:"id-spe-sc-18")
        ]
      },
      {
        "АВТЕНТИФІКАЦІЯ СЕСІЇ (SC-23)",
        [
        CA.SPE.oid(:"id-spe-sc-23")
        ]
      },
      {:category, "ЦІЛІСНІСТЬ СИСТЕМИ ТА ІНФОРМАЦІЇ (SI)"},
      {
        "ВИПРАВЛЕННЯ ДЕФЕКТІВ (SI-2)",
        [
        CA.SPE.oid(:"id-spe-si-2")
        ]
      },
      {
        "ЗАХИСТ ВІД ШКІДЛИВОГО КОДУ (SI-3)",
        [
        CA.SPE.oid(:"id-spe-si-3")
        ]
      },
      {
        "ПОПЕРЕДЖЕННЯ, РЕКОМЕНДАЦІЇ ТА ДИРЕКТИВИ З БЕЗПЕКИ (SI-5)",
        [
        CA.SPE.oid(:"id-spe-si-5")
        ]
      },
      {
        "МОНІТОРИНГ СИСТЕМИ (SI-4)",
        [
        CA.SPE.oid(:"id-spe-si-4"),
        CA.SPE.oid(:"id-spe-si-4-4")
        ]
      },
      {:category, "Політики та процедури з безпеки"},
      {
        "Політики та процедури з безпеки",
        [
        CA.SPE.oid(:"id-spe-ac-1"),
        CA.SPE.oid(:"id-spe-at-1"),
        CA.SPE.oid(:"id-spe-au-1"),
        CA.SPE.oid(:"id-spe-ca-1"),
        CA.SPE.oid(:"id-spe-cm-1"),
        CA.SPE.oid(:"id-spe-ia-1"),
        CA.SPE.oid(:"id-spe-ir-1"),
        CA.SPE.oid(:"id-spe-ma-1"),
        CA.SPE.oid(:"id-spe-mp-1"),
        CA.SPE.oid(:"id-spe-pe-1"),
        CA.SPE.oid(:"id-spe-pl-1"),
        CA.SPE.oid(:"id-spe-ps-1"),
        CA.SPE.oid(:"id-spe-ra-1"),
        CA.SPE.oid(:"id-spe-sa-1"),
        CA.SPE.oid(:"id-spe-sc-1"),
        CA.SPE.oid(:"id-spe-si-1"),
        CA.SPE.oid(:"id-spe-sr-1")
        ]
      },
      {:category, "ПЛАНУВАННЯ (PL)"},
      {
        "ПЛАНИ ЗАХИСТУ ІНФОРМАЦІЇ ТА ПЕРСОНАЛЬНИХ ДАНИХ (PL-2)",
        [
        CA.SPE.oid(:"id-spe-pl-2")
        ]
      }
    ]
  end

  def controls do
    groups() |> Enum.reject(fn
      {:category, _} -> true
      _ -> false
    end) |> Enum.flat_map(fn {_name, controls} -> controls end) |> Enum.uniq()
  end
end
