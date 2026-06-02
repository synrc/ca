defmodule CA.CPTest do
  use ExUnit.Case

  test "CP module provides correct OIDs for Court Systems" do
    assert CA.CP.oid(:"id-cp-ua-court-basic") == {1, 2, 804, 3, 1, 2, 1}
    assert CA.CP.oid(:"id-cp-ua-court-supreme") == {1, 2, 804, 3, 1, 2, 3}
    assert CA.CP.lookup({1, 2, 804, 3, 1, 2, 1}) == "Базовий профіль безпеки (Level 1)"
  end

  test "Simulate certificate issuing with certificatePolicies single-liner" do
    # This test simulates the insertion of the single liner in `CA.CMP.message/4`.
    # cert = X509.Certificate.new(public_key, subject, ca, ca_key,
    #     extensions: [
    #       subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]),
    #       certificate_policies: CA.CP.oid(:"id-cp-ua-court-basic") # <- The single liner
    #     ])

    # We just ensure the syntax is valid Elixir list formatting that X509 extensions expect.
    extensions = [
      subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]),
      certificate_policies: CA.CP.oid(:"id-cp-ua-court-basic")
    ]

    assert Keyword.has_key?(extensions, :certificate_policies)
    assert Keyword.get(extensions, :certificate_policies) == {1, 2, 804, 3, 1, 2, 1}
  end
end
