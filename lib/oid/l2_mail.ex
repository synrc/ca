defmodule CA.L2.Mail do
  @moduledoc """
  Level 2: Military Mail Security Profile (Завдання безпеки для військової пошти)

  Цей профіль розширює базовий (L1) додатковими вимогами, специфічними для
  систем обміну повідомленнями високого рівня захисту (MHS X.420 / STANAG 4406),
  таких як військові поштові системи з підтримкою грифування, S/MIME шифрування
  та неспростовності.

  1. Захист передачі та E2EE (CMS / S/MIME)
     * `SC-8(1)`, `SC-8(2)`: Конфіденційність та цілісність передачі (E2EE/S/MIME).
     * `SC-28(1)`: Шифрування повідомлень у стані спокою на серверах та клієнтських пристроях.

  2. Атрибути безпеки та Грифування (Security Labels)
     * `AC-16`: Управління атрибутами безпеки (маркування та грифування повідомлень).
     * `AC-16(5)`: Маркування суб'єктів та об'єктів для розмежування доступу.

  3. Неспростовність та ЕЦП (Non-repudiation)
     * `AU-10`: Неспростовність повідомлень (Proof of Origin / Proof of Delivery).
     * `AU-10(5)`: Використання цифрових підписів для забезпечення цілісності.

  4. Сувора автентифікація
     * `IA-5(11)`: Використання апаратних токенів (смарт-карток) для доступу.
     * `IA-2(12)`: Підтримка PKI/PIV Credentials.

  5. Інфраструктура та Управління даними
     * `SC-12`, `SC-17`: Інфраструктура PKI та автоматизація ключів.
     * `AC-10`: Обмеження паралельних сесій до поштової скриньки.
     * `MP-6`: Знищення інформації (очищення носіїв).
     * `MP-8(4)`: Пониження грифу таємності (Downgrading) при експорті повідомлень.

  6. Механізм контролю доступу (Reference Monitor)
     * `AC-25`: Reference Monitor (ядро перевірки політик доступу).
     * `AC-3`: Забезпечення доступу (Access Enforcement).

  7. Аудит і Підзвітність
     * `AU-2`: Реєстрація подій (логування рішень щодо доступу - Permit/Deny/NotApplicable).

  8. Бізнес-процеси та Маршрутизація (BPMN)
     * `AC-4`: Управління потоками інформації згідно з BPMN-маршрутами.
     * `CM-5`: Обмеження доступу до зміни BPMN-схем.
     * `AU-12`: Логування транзицій станів процесу.
  """

  def controls do
    CA.L1.controls() ++
      [
        # Crypto / E2EE / S/MIME
        CA.SPE.oid(:"id-spe-sc-8-1"),
        CA.SPE.oid(:"id-spe-sc-8-2"),
        CA.SPE.oid(:"id-spe-sc-28-1"),

        # Labels & Classification
        CA.SPE.oid(:"id-spe-ac-16"),
        CA.SPE.oid(:"id-spe-ac-16-5"),

        # Non-repudiation & Signatures
        CA.SPE.oid(:"id-spe-au-10"),
        CA.SPE.oid(:"id-spe-au-10-5"),

        # Authentication / Hardware Tokens
        CA.SPE.oid(:"id-spe-ia-5-11"),
        CA.SPE.oid(:"id-spe-ia-2-12"),

        # Infrastructure / Data Management
        CA.SPE.oid(:"id-spe-sc-12"),
        CA.SPE.oid(:"id-spe-sc-17"),
        CA.SPE.oid(:"id-spe-ac-10"),
        CA.SPE.oid(:"id-spe-mp-6"),
        CA.SPE.oid(:"id-spe-mp-8-4"),

        # BPMN Routing and Workflow
        CA.SPE.oid(:"id-spe-ac-4"),
        CA.SPE.oid(:"id-spe-cm-5"),
        CA.SPE.oid(:"id-spe-au-12"),

        # ABAC engine
        CA.SPE.oid(:"id-spe-ac-25"),
        CA.SPE.oid(:"id-spe-ac-3"),
        CA.SPE.oid(:"id-spe-au-2")
      ]
  end
end
