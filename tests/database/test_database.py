import pytest
from unittest.mock import AsyncMock
from fastapi import HTTPException
from database.database import get_cve, find_cve_by_id



@pytest.mark.asyncio
async def test_find_cve_by_id_found():
    db_mock = AsyncMock()
    db_mock["cve"].find_one.return_value = {
  "_id": {
    "$oid": "65bb1d4bdb3d2d6a0de94b67"
  },
  "id": "cve-2000-0495",
  "sourceIdentifier": "cve@mitre.org",
  "published": "2000-05-30T04:00:00.000",
  "lastModified": "2018-10-12T21:29:38.920",
  "vulnStatus": "Modified",
  "descriptions": [
    {
      "lang": "en",
      "value": "Microsoft Windows Media Encoder allows remote attackers to cause a denial of service via a malformed request, aka the \"Malformed Windows Media Encoder Request\" vulnerability."
    }
  ],
  "metrics": {
    "cvssMetricV2": [
      {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
          "version": "2.0",
          "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
          "accessVector": "NETWORK",
          "accessComplexity": "LOW",
          "authentication": "NONE",
          "confidentialityImpact": "NONE",
          "integrityImpact": "NONE",
          "availabilityImpact": "PARTIAL",
          "baseScore": 5
        },
        "baseSeverity": "MEDIUM",
        "exploitabilityScore": 10,
        "impactScore": 2.9,
        "acInsufInfo": False,
        "obtainAllPrivilege": False,
        "obtainUserPrivilege": False,
        "obtainOtherPrivilege": False,
        "userInteractionRequired": False
      }
    ]
  },
  "weaknesses": [
    {
      "source": "nvd@nist.gov",
      "type": "Primary",
      "description": [
        {
          "lang": "en",
          "value": "NVD-CWE-Other"
        }
      ]
    }
  ],
  "configurations": [
    {
      "nodes": [
        {
          "operator": "OR",
          "negate": False,
          "cpeMatch": [
            {
              "vulnerable": True,
              "criteria": "cpe:2.3:a:microsoft:windows_media_services:4.0:*:*:*:*:*:*:*",
              "matchCriteriaId": "D073958F-0428-4E15-97B0-8EDAD0E80632"
            },
            {
              "vulnerable": True,
              "criteria": "cpe:2.3:a:microsoft:windows_media_services:4.1:*:*:*:*:*:*:*",
              "matchCriteriaId": "AA3DDE73-E623-45A3-AA49-17BAFB89A2CC"
            }
          ]
        }
      ]
    }
  ],
  "references": [
    {
      "url": "http://www.securityfocus.com/bid/1282",
      "source": "cve@mitre.org"
    },
    {
      "url": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-038",
      "source": "cve@mitre.org"
    },
    {
      "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/4585",
      "source": "cve@mitre.org"
    }
  ]
}

    cve = await find_cve_by_id("cve-2000-0495", db=db_mock)

    assert cve is not None

@pytest.mark.asyncio
async def test_find_cve_by_id_not_found():
    
    db_mock = AsyncMock()
    db_mock["cve"].find_one.return_value = None

    with pytest.raises(HTTPException):
        await find_cve_by_id("non-existent-cve-id", db=db_mock)
