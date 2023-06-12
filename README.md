# CA: Certificate Authority

[![Actions Status](https://github.com/synrc/ca/workflows/mix/badge.svg)](https://github.com/synrc/ca/actions)
[![Build Status](https://travis-ci.com/synrc/ca.svg?branch=master)](https://travis-ci.com/synrc/ca)
[![Hex pm](http://img.shields.io/hexpm/v/ca.svg?style=flat)](https://hex.pm/packages/ca)

![ca-shaders](https://github.com/synrc/ca/assets/144776/f8f9c280-9442-443e-a2be-7d610a1a7815)

## X.509 decode SignData

```elixir
> {:ok,bin} = :file.read_file("priv/5HT.p7s")
> KEP.parseSignData bin
{{:certAttrs, "1786046", "СОХАЦЬКИЙ МАКСИМ ЕРОТЕЙОВИЧ",
  "МАКСИМ ЕРОТЕЙОВИЧ", "СОХАЦЬКИЙ",
  "СОХАЦЬКИЙ МАКСИМ ЕРОТЕЙОВИЧ",
  "Електронна печатка", "", 'UA', "КИЇВ"},
 {:certAttrs, "UA-14360570-2018", "АЦСК АТ КБ «ПРИВАТБАНК»",
  "", "",
  "АКЦІОНЕРНЕ ТОВАРИСТВО КОМЕРЦІЙНИЙ БАНК «ПРИВАТБАНК»",
  "", "АЦСК", 'UA', "Київ"}}
```

## X.509 decode Cert

```elixir
{{:certAttrs, "8", "А0 Адміністратор Тестовий",
  "Адміністратор Тестовий", "А0",
  "ДП \"Інфотех\"34_ТЕСТ", "Адміністратор",
  "Відділ розробки інформаційних систем", 'UA',
  "Київ"},
 {:certAttrs, "UA-00015622-2012", "АЦСК МВС України (ТЕСТ)",
  "", "",
  "Міністерство внутрішніх справ України", "",
  "Департамент інформаційних технологій",
  'UA', "Київ"},
 [
   subjectKeyIdentifier: [
     <<33, 173, 19, 32, 70, 1, 81, 17, 70, 101, 22, 104, 149, 193, 81, 68, 44,
       51, 97, 255, 25, 32, 89, 34, 21, 29, 64, 166, 8, 148, 81, 30>>
   ],
   authorityKeyIdentifier: [
     <<199, 135, 206, 81, 158, 165, 41, 3, 146, 14, 164, 157, 92, 172, 74, 104,
       243, 247, 233, 222, 181, 197, 233, 92, 122, 205, 167, 37, 144, 171, 44,
       161>>
   ],
   privateKeyUsagePeriod: ["20200803210000Z", "20210803210000Z"],
   keyUsage: [<<6, 192>>],
   certificatePolicies: {1, 2, 804, 2, 1, 1, 1, 2, 2},
   basicConstraints: [],
   qcStatements: {1, 2, 804, 2, 1, 1, 1, 2, 1},
   subjectAltName: [
     "info@infotech.gov.ua",
     {{1, 3, 6, 1, 4, 1, 19398, 1, 1, 4, 1}, "+38 (0 67) 663-18-70"},
     {{1, 3, 6, 1, 4, 1, 19398, 1, 1, 4, 2},
      "04050, м. Київ, вул. Дегтярівська, 15Б"}
   ],
   cRLDistributionPoints: ["http://cat.mvs.gov.ua/download/crls/CA-C787CE51-Full.crl"],
   freshestCRL: ["http://cat.mvs.gov.ua/download/crls/CA-C787CE51-Delta.crl"],
   authorityInfoAccess: [
     {{1, 3, 6, 1, 5, 5, 7, 48, 2},
      "http://cat.mvs.gov.ua/download/certificates/cat.p7b"},
     {{1, 3, 6, 1, 5, 5, 7, 48, 1}, "http://cat.mvs.gov.ua/services/ocsp/"}
   ],
   subjectInfoAccess: [
     {{1, 3, 6, 1, 5, 5, 7, 48, 3}, "http://cat.mvs.gov.ua/services/tsp/"}
   ],
   subjectDirectoryAttributes: [
     {{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 11, 1}, "19950415-00026"},
     {{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 1, 1}, "1234006530"},
     {{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 2, 1}, "31239034"}
   ]
 ]}
```

## Mentions

* <a href="https://tonpa.guru/stream/2020/2020-02-03%20%D0%9A%D0%B2%D0%B0%D0%BB%D1%96%D1%84%D1%96%D0%BA%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B9%20%D0%95%D0%BB%D0%B5%D0%BA%D1%82%D1%80%D0%BE%D0%BD%D0%BD%D0%B8%D0%B9%20%D0%9F%D1%96%D0%B4%D0%BF%D0%B8%D1%81.htm">2020-02-03 Кваліфікований Електронний Підпис</a>

## Credits

Максим Сохацький
