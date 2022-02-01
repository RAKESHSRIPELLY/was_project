import time
import random

dashboard_applications = {
    "application_1": {
        "application_id": "application_1",
        "application_name": "App1"
    },
    "application_2": {
        "application_id": "application_2",
        "application_name": "App2"
    },
    "application_3": {
        "application_id": "application_3",
        "application_name": "App3"
    },
    "application_4": {
        "application_id": "application_4",
        "application_name": "App4"
    },
    "application_5": {
        "application_id": "application_5",
        "application_name": "App5"
    }
}

dashboard = {
    "vulnerability_count": {
        "total": random.randint(1, 99),
        "severity": {
            "critical": random.randint(1, 99),
            "high": random.randint(1, 99),
            "medium": random.randint(1, 99),
            "low": random.randint(1, 99)
        }
    },
    "top_vulnerabilities": {
        "vulnerability_1": {
            "vulnerability_id": "vulnerability_1",
            "vulnerability_name": "SQL Injection 1",
            "cwe_id": random.randint(1, 99),
            "cwe_reference": "",
            "cvss_score": round(random.uniform(1.0, 9.0), 1),
            "frequency": random.randint(1, 99)
        },
        "vulnerability_2": {
            "vulnerability_id": "vulnerability_2",
            "vulnerability_name": "SQL Injection 2",
            "cwe_id": random.randint(1, 99),
            "cwe_reference": "",
            "cvss_score": round(random.uniform(1.0, 9.0), 1),
            "frequency": random.randint(1, 99)
        },
        "vulnerability_3": {
            "vulnerability_id": "vulnerability_3",
            "vulnerability_name": "SQL Injection 3",
            "cwe_id": random.randint(1, 99),
            "cwe_reference": "",
            "cvss_score": round(random.uniform(1.0, 9.0), 1),
            "frequency": random.randint(1, 99)
        },
        "vulnerability_4": {
            "vulnerability_id": "vulnerability_4",
            "vulnerability_name": "SQL Injection 4",
            "cwe_id": random.randint(1, 99),
            "cwe_reference": "",
            "cvss_score": round(random.uniform(1.0, 9.0), 1),
            "frequency": random.randint(1, 99)
        },
        "vulnerability_5": {
            "vulnerability_id": "vulnerability_5",
            "vulnerability_name": "SQL Injection 5",
            "cwe_id": random.randint(1, 99),
            "cwe_reference": "",
            "cvss_score": round(random.uniform(1.0, 9.0), 1),
            "frequency": random.randint(1, 99)
        }
    },
    "vulnerable_applications": {
        "application_1": {
            "application_id": "application_1",
            "application_name": "Webgoat",
            "total": random.randint(1, 100),
            "severity": {
                "critical": random.randint(1, 100),
                "high": random.randint(1, 100),
                "medium": random.randint(1, 100),
                "low": random.randint(1, 100)
            }
        },
        "application_2": {
            "application_id": "application_2",
            "application_name": "Jenkins",
            "total": random.randint(1, 100),
            "severity": {
                "critical": random.randint(1, 100),
                "high": random.randint(1, 100),
                "medium": random.randint(1, 100),
                "low": random.randint(1, 100)
            }
        },
        "application_3": {
            "application_id": "application_3",
            "application_name": "Jira",
            "total": random.randint(1, 100),
            "severity": {
                "critical": random.randint(1, 100),
                "high": random.randint(1, 100),
                "medium": random.randint(1, 100),
                "low": random.randint(1, 100)
            }
        },
        "application_4": {
            "application_id": "application_4",
            "application_name": "Struts",
            "total": random.randint(1, 100),
            "severity": {
                "critical": random.randint(1, 100),
                "high": random.randint(1, 100),
                "medium": random.randint(1, 100),
                "low": random.randint(1, 100)
            }
        },
        "application_5": {
            "application_id": "application_5",
            "application_name": "Classifieds",
            "total": random.randint(1, 100),
            "severity": {
                "critical": random.randint(1, 100),
                "high": random.randint(1, 100),
                "medium": random.randint(1, 100),
                "low": random.randint(1, 100)
            }
        }

    },
    "applications_not_scanned": {
        "application_1": {
            "application_id": "application_1",
            "application_name": "App1",
            "last_scanned": 1601124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "application_2": {
            "application_id": "application_2",
            "application_name": "App2",
            "last_scanned": 1602124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "application_3": {
            "application_id": "application_3",
            "application_name": "App3",
            "last_scanned": 1603124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "application_4": {
            "application_id": "application_4",
            "application_name": "App4",
            "last_scanned": 1604124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "application_5": {
            "application_id": "application_5",
            "application_name": "App5",
            "last_scanned": 1605124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "application_6": {
            "application_id": "application_6",
            "application_name": "App6",
            "last_scanned": 1606124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "application_7": {
            "application_id": "application_7",
            "application_name": "App7",
            "last_scanned": 1607124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "application_8": {
            "application_id": "application_8",
            "application_name": "App8",
            "last_scanned": 1608124449,
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        }
    },
    "vulnerabilities_by_scan":{
        "application_1": {
            "application_id": "application_1",
            "application_name": "App1",
            "status": {
                "scan_time": 1601111449,
                "open": random.randint(1, 99),
                "resolved": random.randint(1, 99),
                "new": random.randint(1, 99)
            }
        },
        "application_2": {
            "application_id": "application_2",
            "application_name": "App2",
            "status": {
                "scan_time": 1601121449,
                "open": random.randint(1, 99),
                "resolved": random.randint(1, 99),
                "new": random.randint(1, 99)
            }
        },
        "application_3": {
            "application_id": "application_3",
            "application_name": "App3",
            "status": {
                "scan_time": 1601131449,
                "open": random.randint(1, 99),
                "resolved": random.randint(1, 99),
                "new": random.randint(1, 99)
            }
        },
        "application_4": {
            "application_id": "application_4",
            "application_name": "App4",
            "status": {
                "scan_time": 1601141449,
                "open": random.randint(1, 99),
                "resolved": random.randint(1, 99),
                "new": random.randint(1, 99)
            }
        },
        "application_5": {
            "application_id": "application_5",
            "application_name": "App5",
            "status": {
                "scan_time": 1601151449,
                "open": random.randint(1, 99),
                "resolved": random.randint(1, 99),
                "new": random.randint(1, 99)
            }
        }
    }
}

for i in range(10):
    dashboard_app1 = {
        "vulnerability_count": {
            "total": random.randint(1, 99),
            "severity": {
                "critical": random.randint(1, 99),
                "high": random.randint(1, 99),
                "medium": random.randint(1, 99),
                "low": random.randint(1, 99)
            }
        },
        "top_vulnerabilities": {
            "vulnerability_1": {
                "vulnerability_id": "vulnerability_1",
                "vulnerability_name": "SQL Injection 1",
                "cwe_id": random.randint(1, 99),
                "cwe_reference": "",
                "cvss_score": round(random.uniform(1.0, 9.0), 1),
                "frequency": random.randint(1, 99)
            },
            "vulnerability_2": {
                "vulnerability_id": "vulnerability_2",
                "vulnerability_name": "SQL Injection 2",
                "cwe_id": random.randint(1, 99),
                "cwe_reference": "",
                "cvss_score": round(random.uniform(1.0, 9.0), 1),
                "frequency": random.randint(1, 99)
            },
            "vulnerability_3": {
                "vulnerability_id": "vulnerability_3",
                "vulnerability_name": "SQL Injection 3",
                "cwe_id": random.randint(1, 99),
                "cwe_reference": "",
                "cvss_score": round(random.uniform(1.0, 9.0), 1),
                "frequency": random.randint(1, 99)
            },
            "vulnerability_4": {
                "vulnerability_id": "vulnerability_4",
                "vulnerability_name": "SQL Injection 4",
                "cwe_id": random.randint(1, 99),
                "cwe_reference": "",
                "cvss_score": round(random.uniform(1.0, 9.0), 1),
                "frequency": random.randint(1, 99)
            },
            "vulnerability_5": {
                "vulnerability_id": "vulnerability_5",
                "vulnerability_name": "SQL Injection 5",
                "cwe_id": random.randint(1, 99),
                "cwe_reference": "",
                "cvss_score": round(random.uniform(1.0, 9.0), 1),
                "frequency": random.randint(1, 99)
            }
        },
        "vulnerable_applications": {
            "application_1": {
                "application_id": "application_1",
                "application_name": "Webgoat",
                "total": random.randint(1, 100),
                "severity": {
                    "critical": random.randint(1, 100),
                    "high": random.randint(1, 100),
                    "medium": random.randint(1, 100),
                    "low": random.randint(1, 100)
                }
            },
            "application_2": {
                "application_id": "application_2",
                "application_name": "Jenkins",
                "total": random.randint(1, 100),
                "severity": {
                    "critical": random.randint(1, 100),
                    "high": random.randint(1, 100),
                    "medium": random.randint(1, 100),
                    "low": random.randint(1, 100)
                }
            },
            "application_3": {
                "application_id": "application_3",
                "application_name": "Jira",
                "total": random.randint(1, 100),
                "severity": {
                    "critical": random.randint(1, 100),
                    "high": random.randint(1, 100),
                    "medium": random.randint(1, 100),
                    "low": random.randint(1, 100)
                }
            },
            "application_4": {
                "application_id": "application_4",
                "application_name": "Struts",
                "total": random.randint(1, 100),
                "severity": {
                    "critical": random.randint(1, 100),
                    "high": random.randint(1, 100),
                    "medium": random.randint(1, 100),
                    "low": random.randint(1, 100)
                }
            },
            "application_5": {
                "application_id": "application_5",
                "application_name": "Classifieds",
                "total": random.randint(1, 100),
                "severity": {
                    "critical": random.randint(1, 100),
                    "high": random.randint(1, 100),
                    "medium": random.randint(1, 100),
                    "low": random.randint(1, 100)
                }
            }

        },
        "applications_not_scanned": {
            "application_1": {
                "application_id": "application_1",
                "application_name": "App1",
                "last_scanned": 1601124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            },
            "application_2": {
                "application_id": "application_2",
                "application_name": "App2",
                "last_scanned": 1602124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            },
            "application_3": {
                "application_id": "application_3",
                "application_name": "App3",
                "last_scanned": 1603124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            },
            "application_4": {
                "application_id": "application_4",
                "application_name": "App4",
                "last_scanned": 1604124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            },
            "application_5": {
                "application_id": "application_5",
                "application_name": "App5",
                "last_scanned": 1605124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            },
            "application_6": {
                "application_id": "application_6",
                "application_name": "App6",
                "last_scanned": 1606124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            },
            "application_7": {
                "application_id": "application_7",
                "application_name": "App7",
                "last_scanned": 1607124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            },
            "application_8": {
                "application_id": "application_8",
                "application_name": "App8",
                "last_scanned": 1608124449,
                "total": random.randint(1, 99),
                "severity": {
                    "critical": random.randint(1, 99),
                    "high": random.randint(1, 99),
                    "medium": random.randint(1, 99),
                    "low": random.randint(1, 99)
                }
            }
        },
        "vulnerabilities_by_scan": {
            "application_1": {
                "application_id": "application_1",
                "application_name": "App1",
                "status": {
                    "scan_time": 1601111449,
                    "open": random.randint(1, 99),
                    "resolved": random.randint(1, 99),
                    "new": random.randint(1, 99)
                }
            },
            "application_2": {
                "application_id": "application_2",
                "application_name": "App2",
                "status": {
                    "scan_time": 1601121449,
                    "open": random.randint(1, 99),
                    "resolved": random.randint(1, 99),
                    "new": random.randint(1, 99)
                }
            },
            "application_3": {
                "application_id": "application_3",
                "application_name": "App3",
                "status": {
                    "scan_time": 1601131449,
                    "open": random.randint(1, 99),
                    "resolved": random.randint(1, 99),
                    "new": random.randint(1, 99)
                }
            },
            "application_4": {
                "application_id": "application_4",
                "application_name": "App4",
                "status": {
                    "scan_time": 1601141449,
                    "open": random.randint(1, 99),
                    "resolved": random.randint(1, 99),
                    "new": random.randint(1, 99)
                }
            },
            "application_5": {
                "application_id": "application_5",
                "application_name": "App5",
                "status": {
                    "scan_time": 1601151449,
                    "open": random.randint(1, 99),
                    "resolved": random.randint(1, 99),
                    "new": random.randint(1, 99)
                }
            }
        }
    }


report = {
    "application_id": "5e3419db9a00f81d95f38832",
    "report_id": "report_1",
    "report_name": "Application_Test_1",
    "report_version": "1.0.0",
    "application_under_test": {
        "application_id": "5e3419db9a00f81d95f38832",
        "application_name": "Application_Test_1",
        "application_version": "1.2.3",
        "application_url": "http://application_test_1.com",
        "application_user": "application_user@bookstore.com",
        "scan_datetime": time.time(),
        "scan_start_time": "",
        "scan_end_time": "",
        "scan_profile": "",
        "was_instance": "10.0.0.1",
        "user_email": "admin@test.com"

    },
    "vulnerability_distribution": {
        "severity": {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        },
        "urls_crawled": 15,
        "total_alerts": 10
    },
    "services": {
        "service_1": {
            "service_id": "service_1",
            "service_url": "serviceurl1.com",
            "vulnerabilities": {
                "vulnerability_1": {
                    "vulnerabilility_id": "vulnerability_1",
                    "vulnerability_name": "SQL Injection",
                    "vulnerability_description": "",
                    "affected_items": "",
                    "risk_factor": "critical",
                    "urls": {
                        "url_1": {
                            "url_id": "url_1",
                            "url": "http://www.test11.com",
                            "parameter": {
                                "parameter_id": "parameter_1",
                                "parameter_name": "",
                                "summary": {
                                    "http_response": "",
                                    "http_response_code": ""
                                }
                            }
                        },
                        "url_2": {
                            "url_id": "url_2",
                            "url": "http://www.test12.com",
                            "parameter": {
                                "parameter_id": "parameter_1",
                                "parameter_name": "",
                                "summary": {
                                    "http_response": "",
                                    "http_response_code": ""
                                }
                            }
                        }
                    },
                    "recommendations": {
                        "recommendation_1": {
                            "recommendation_id": "recommendation_1",
                            "recommendation_description": "test_description1"
                        },
                        "recommendation_2": {
                            "recommendation_id": "recommendation_2",
                            "recommendation_description": "test_description2"
                        }
                    },
                    "references": {
                        "link_1": {
                            "link_id": "link_1",
                            "link": "http://www.testlink1.com"
                        },
                        "link_2": {
                            "link_id": "link_2",
                            "link": "http://www.testlink1.com"
                        },
                        "link_3": {
                            "link_id": "link_3",
                            "link": "http://www.testlink1.com"
                        }
                    },
                    "vulnerability_classification": {
                        "cwe": {
                            "cwe_1": {
                                "cwe_id": "cwe_1",
                                "cwe_description": "test_description1"
                            },
                            "cwe_2": {
                                "cwe_id": "cwe_2",
                                "cwe_description": "test_description2"
                            }
                        },
                        "capec": {
                            "capec_1": {
                                "capec_id": "cwe_1",
                                "capec_description": "test_description1"
                            },
                            "capec_2": {
                                "capec_id": "cwe_2",
                                "capec_description": "test_description2"
                            }
                        },
                        "owasp": {
                            "owasp_1": {
                                "owasp_id": "owasp_1",
                                "owasp_description": "test_description1"
                            },
                            "owasp_2": {
                                "owasp_id": "owasp_2",
                                "owasp_description": "test_description2"
                            }
                        },
                        "sans": {
                            "sans_1": {
                                "sans_id": "sans_1",
                                "sans_description": "test_description1"
                            },
                            "sans_2": {
                                "sans_id": "sans_2",
                                "sans_description": "test_description2"
                            }
                        }
                    }
                },
                "vulnerability_2": {
                    "vulnerabilility_id": "vulnerability_2",
                    "vulnerability_name": "SQL Injection",
                    "vulnerability_description": "",
                    "affected_items": "",
                    "risk_factor": "high",
                    "urls": {
                        "url_1": {
                            "url_id": "url_1",
                            "url": "http://www.test21.com",
                            "parameter": ""
                        },
                        "url_2": {
                            "url_id": "url_2",
                            "url": "http://www.test22.com",
                            "parameter": ""
                        }
                    },
                    "recommendations": {
                        "recommendation_1": {
                            "recommendation_id": "recommendation_1",
                            "recommendation_description": "test_description1"
                        },
                        "recommendation_2": {
                            "recommendation_id": "recommendation_2",
                            "recommendation_description": "test_description2"
                        }
                    },
                    "references": {},
                    "vulnerability_classification": {
                        "cwe": {
                            "cwe_1": {
                                "cwe_id": "cwe_1",
                                "cwe_description": "test_description1"
                            },
                            "cwe_2": {
                                "cwe_id": "cwe_2",
                                "cwe_description": "test_description2"
                            }
                        },
                        "capec": {
                            "capec_1": {
                                "capec_id": "cwe_1",
                                "capec_description": "test_description1"
                            },
                            "capec_2": {
                                "capec_id": "cwe_2",
                                "capec_description": "test_description2"
                            }
                        },
                        "owasp": {
                            "owasp_1": {
                                "owasp_id": "owasp_1",
                                "owasp_description": "test_description1"
                            },
                            "owasp_2": {
                                "owasp_id": "owasp_2",
                                "owasp_description": "test_description2"
                            }
                        },
                        "sans": {
                            "sans_1": {
                                "sans_id": "sans_1",
                                "sans_description": "test_description1"
                            },
                            "sans_2": {
                                "sans_id": "sans_2",
                                "sans_description": "test_description2"
                            }
                        }
                    }
                },
                "vulnerability_3": {
                    "vulnerabilility_id": "vulnerability_3",
                    "vulnerability_name": "SQL Injection",
                    "vulnerability_description": "",
                    "affected_items": "",
                    "risk_factor": "medium",
                    "urls": {
                        "url_1": {
                            "url_id": "url_1",
                            "url": "http://www.test21.com",
                            "parameter": ""
                        },
                        "url_2": {
                            "url_id": "url_2",
                            "url": "http://www.test22.com",
                            "parameter": ""
                        }
                    },
                    "recommendations": {
                        "recommendation_1": {
                            "recommendation_id": "recommendation_1",
                            "recommendation_description": "test_description1"
                        },
                        "recommendation_2": {
                            "recommendation_id": "recommendation_2",
                            "recommendation_description": "test_description2"
                        }
                    },
                    "references": {},
                    "vulnerability_classification": {
                        "cwe": {
                            "cwe_1": {
                                "cwe_id": "cwe_1",
                                "cwe_description": "test_description1"
                            },
                            "cwe_2": {
                                "cwe_id": "cwe_2",
                                "cwe_description": "test_description2"
                            }
                        },
                        "capec": {
                            "capec_1": {
                                "capec_id": "cwe_1",
                                "capec_description": "test_description1"
                            },
                            "capec_2": {
                                "capec_id": "cwe_2",
                                "capec_description": "test_description2"
                            }
                        },
                        "owasp": {
                            "owasp_1": {
                                "owasp_id": "owasp_1",
                                "owasp_description": "test_description1"
                            },
                            "owasp_2": {
                                "owasp_id": "owasp_2",
                                "owasp_description": "test_description2"
                            }
                        },
                        "sans": {
                            "sans_1": {
                                "sans_id": "sans_1",
                                "sans_description": "test_description1"
                            },
                            "sans_2": {
                                "sans_id": "sans_2",
                                "sans_description": "test_description2"
                            }
                        }
                    }
                },
                "vulnerability_4": {
                    "vulnerabilility_id": "vulnerability_4",
                    "vulnerability_name": "SQL Injection",
                    "vulnerability_description": "",
                    "affected_items": "",
                    "risk_factor": "low",
                    "urls": {
                        "url_1": {
                            "url_id": "url_1",
                            "url": "http://www.test21.com",
                            "parameter": ""
                        },
                        "url_2": {
                            "url_id": "url_2",
                            "url": "http://www.test22.com",
                            "parameter": ""
                        }
                    },
                    "recommendations": {
                        "recommendation_1": {
                            "recommendation_id": "recommendation_1",
                            "recommendation_description": "test_description1"
                        },
                        "recommendation_2": {
                            "recommendation_id": "recommendation_2",
                            "recommendation_description": "test_description2"
                        }
                    },
                    "references": {},
                    "vulnerability_classification": {
                        "cwe": {
                            "cwe_1": {
                                "cwe_id": "cwe_1",
                                "cwe_description": "test_description1"
                            },
                            "cwe_2": {
                                "cwe_id": "cwe_2",
                                "cwe_description": "test_description2"
                            }
                        },
                        "capec": {
                            "capec_1": {
                                "capec_id": "cwe_1",
                                "capec_description": "test_description1"
                            },
                            "capec_2": {
                                "capec_id": "cwe_2",
                                "capec_description": "test_description2"
                            }
                        },
                        "owasp": {
                            "owasp_1": {
                                "owasp_id": "owasp_1",
                                "owasp_description": "test_description1"
                            },
                            "owasp_2": {
                                "owasp_id": "owasp_2",
                                "owasp_description": "test_description2"
                            }
                        },
                        "sans": {
                            "sans_1": {
                                "sans_id": "sans_1",
                                "sans_description": "test_description1"
                            },
                            "sans_2": {
                                "sans_id": "sans_2",
                                "sans_description": "test_description2"
                            }
                        }
                    }
                },
                "vulnerability_5": {
                    "vulnerabilility_id": "vulnerability_4",
                    "vulnerability_name": "SQL Injection",
                    "vulnerability_description": "",
                    "affected_items": "",
                    "risk_factor": "info",
                    "urls": {
                        "url_1": {
                            "url_id": "url_1",
                            "url": "http://www.test21.com",
                            "parameter": ""
                        },
                        "url_2": {
                            "url_id": "url_2",
                            "url": "http://www.test22.com",
                            "parameter": ""
                        }
                    },
                    "recommendations": {
                        "recommendation_1": {
                            "recommendation_id": "recommendation_1",
                            "recommendation_description": "test_description1"
                        },
                        "recommendation_2": {
                            "recommendation_id": "recommendation_2",
                            "recommendation_description": "test_description2"
                        }
                    },
                    "references": {},
                    "vulnerability_classification": {
                        "cwe": {
                            "cwe_1": {
                                "cwe_id": "cwe_1",
                                "cwe_description": "test_description1"
                            },
                            "cwe_2": {
                                "cwe_id": "cwe_2",
                                "cwe_description": "test_description2"
                            }
                        },
                        "capec": {
                            "capec_1": {
                                "capec_id": "cwe_1",
                                "capec_description": "test_description1"
                            },
                            "capec_2": {
                                "capec_id": "cwe_2",
                                "capec_description": "test_description2"
                            }
                        },
                        "owasp": {
                            "owasp_1": {
                                "owasp_id": "owasp_1",
                                "owasp_description": "test_description1"
                            },
                            "owasp_2": {
                                "owasp_id": "owasp_2",
                                "owasp_description": "test_description2"
                            }
                        },
                        "sans": {
                            "sans_1": {
                                "sans_id": "sans_1",
                                "sans_description": "test_description1"
                            },
                            "sans_2": {
                                "sans_id": "sans_2",
                                "sans_description": "test_description2"
                            }
                        }
                    }
                }
            }
            }
        }
    }


cc_copy = {
                "vulnerabilility_id": "vulnerability_1",
                "vulnerability_name": "SQL Injection",
                "vulnerability_description": "",
                "affected_items": "",
                "risk_factor": "critical",
                "urls": {
                    "url_1": {
                        "url_id": "url_1",
                        "url": "http://www.test11.com",
                        "parameter": ""
                    }
                },
                "recommendation": ""
            }
vul_list = ['low', 'medium', 'high', 'critical', 'info']
import random
cc= list()
for i in range(100):
    cc_copy = {
        "vulnerabilility_id": f"vulnerability_{i}",
        "vulnerability_name": f"SQL Injection {i}",
        "vulnerability_description": "Test description",
        "affected_items": f"{i}",
        "risk_factor": random.choice(vul_list),
        "urls": {
            "url_1": {
                "url_id": f"url_{i}",
                "url": f"http://www.test1{i}.com",
                "parameter": f"test{i}"
            }
        },
        "recommendation": ""
    }
    cc.append(cc_copy)

compensating_control_get = {
    "compensating_control": {
        "report_id": "report_1",
        "vulnerabilities": {
            "vulnerability_1": {
                "vulnerabilility_id": "vulnerability_1",
                "vulnerability_name": "SQL Injection",
                "vulnerability_description": "",
                "affected_items": "",
                "risk_factor": "critical",
                "urls": {
                    "url_1": {
                        "url_id": "url_1",
                        "url": "http://www.test11.com",
                        "parameter": ""
                    }
                },
                "recommendation": ""
            },
            "vulnerability_2": {
                "vulnerabilility_id": "vulnerability_2",
                "vulnerability_name": "SQL Injection",
                "vulnerability_description": "",
                "affected_items": "",
                "risk_factor": "critical",
                "urls": {
                    "url_1": {
                        "url_id": "url_1",
                        "url": "http://www.test21.com",
                        "parameter": ""
                    },
                    "url_2": {
                        "url_id": "url_2",
                        "url": "http://www.test22.com",
                        "parameter": ""
                    }
                },
                "recommendation": ""
            }
        }
    }
}


zoooo = {
    "application_id": "5e3419db9a00f81d95f38832",
    "report_id": "report_1",
    "report_name": "Application_Test_1",
    "report_version": "1.0.0",
    "application_under_test": {
        "application_id": "5e3419db9a00f81d95f38832",
        "application_name": "Application_Test_1",
        "application_version": "1.2.3",
        "application_url": "http://application_test_1.com",
        "scan_date": "Wed 11 Nov 2020",
        "scan_time": "1234",
        "scan_start_time": "",
        "scan_end_time": "",
        "scan_profile": "",
        "was_instance": "10.0.0.1",
        "user_email": "admin@test.com",
        "application_user": "application_user@bookstore.com"
    },
    "organization_summary": {
        "organization": "Virsec",
        "business_unit": "Engineering"
    },
    "reports": [
        {
            "host": {
                "ipv4_address": "10.0.0.2",
                "port": "8080",
                "vulnerabilities": ["reflectivexss", "sqli", "cmdi", "pathtraversal"],
                "executive_summary": {
                    "urls_crawled": "",
                    "total_alerts": 10,
                    "severity": {
                        "critical": 1,
                        "high": 2,
                        "medium": 3,
                        "low": 4
                    }
                },
                "detailed_summary": [
                    {
                        "url_1": {
                            "url_id": "url_1",
                            "request_type": "GET",
                            "uri": "/bookstore/Registration.jsp",
                            "parameters": []
                        }
                    },
                    {
                        "url_2": {
                            "url_id": "url_2",
                            "request_type": "GET",
                            "uri": "/bookstore/MembersGrid.jsp",
                            "parameters": [
                                {
                                    "parameter_id": "id",
                                    "parameter_name": "name",
                                    "vulnerability_summary": {
                                            "payload_id": "",
                                            "payload_type": "",
                                            "payload_description": "A1_SQLi",
                                            "payload_structure": "&#x27;and ascii (substring (1,1)) = 49 - - ",
                                            "interpreter": "",
                                            "capec_id": "",
                                            "capec_description": "Blind SQL Injection",
                                            "cwe_id": "",
                                            "cwe_description": "",
                                            "cvss_severity": "",
                                            "cvss_score": "",
                                            "http_response_code": 200,
                                            "http_response": "",
                                            "reference": "",
                                            "sans": "",
                                            "owasp": "",
                                            "recommendation": ""
                                        }
                                }
                            ]
                        }
                    }
                ]
            }
        }
    ]
}

transactions = {'transactions':
                   {
                       'test_transaction_1': {'transaction_id': 'test_transaction_1', 'transaction_name': 'transaction1', 'urls': {'url_1': {'url_id': 'url_1', 'attack_url': '/bookstore/Login.jsp','request_type': 'POST', 'more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2', 'attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_2': {'transaction_id': 'test_transaction_2', 'transaction_name': 'transaction2', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_3': {'transaction_id': 'test_transaction_3', 'transaction_name': 'transaction3', 'urls': {'url_1': {'url_id': 'url_1', 'attack_url': '/bookstore/Login.jsp','request_type': 'POST', 'more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2', 'attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_4': {'transaction_id': 'test_transaction_4', 'transaction_name': 'transaction4', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_5': {'transaction_id': 'test_transaction_5', 'transaction_name': 'transaction5', 'urls': {'url_1': {'url_id': 'url_1', 'attack_url': '/bookstore/Login.jsp','request_type': 'POST', 'more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2', 'attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_6': {'transaction_id': 'test_transaction_6', 'transaction_name': 'transaction6', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_7': {'transaction_id': 'test_transaction_7', 'transaction_name': 'transaction7', 'urls': {'url_1': {'url_id': 'url_1', 'attack_url': '/bookstore/Login.jsp','request_type': 'POST', 'more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2', 'attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_8': {'transaction_id': 'test_transaction_8', 'transaction_name': 'transaction8', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_9': {'transaction_id': 'test_transaction_9', 'transaction_name': 'transaction9', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_10': {'transaction_id': 'test_transaction_10', 'transaction_name': 'transaction10', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_11': {'transaction_id': 'test_transaction_11', 'transaction_name': 'transaction11', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_12': {'transaction_id': 'test_transaction_12', 'transaction_name': 'transaction12', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_13': {'transaction_id': 'test_transaction_13', 'transaction_name': 'transaction13', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_14': {'transaction_id': 'test_transaction_14', 'transaction_name': 'transaction14', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}},
                       'test_transaction_15': {'transaction_id': 'test_transaction_15', 'transaction_name': 'transaction15', 'urls': {'url_1': {'url_id': 'url_1','attack_url': '/bookstore/Login.jsp', 'request_type': 'POST','more_ids': {'Login': 'admin', 'Password': 'admin', 'FormName': 'Login', 'FormAction': 'login', 'ret_page': '', 'querystring': ''}}, 'url_2': {'url_id': 'url_2','attack_url': '/help.action', 'request_type': 'GET', 'more_ids': {}}}}

                   }
            }

configuration = {"configuration": {
    "cms": {
        "ipv4_address": "",
        "username": "",
        "password": "",
        "authorization_token": "Y21zLXdlYi1jbGllbnQ6Y21zLXdlYi1wYXNz"
    },
    "vsp": {
        "ipv4_address": "",
        "username": "admin",
        "password": "password"
    },
    "integration": {
        "ipv4_address": "",
        "username": "admin",
        "password": "password"
    },
    "proxy": {
        "ipv4_address": "",
        "username": "admin",
        "password": "password",
        "authentication": False
    },
    "syslog": {
        "ipv4_address": "",
        "username": "admin",
        "password": "password"
    },
    "file_size": {
        "authentication_automated": 50,
        "pre_crawl": 50,
        "transaction_store": 50
    },
    "api_version": "1.0"
}}

config_vault = {
        "configuration": {
            "cms": {
                "encrypted_password": "",
                "key": ""
            },
            "integration": {
                "encrypted_password": "",
                "key": ""
            },
            "proxy": {
                "encrypted_password": "",
                "key": ""
            },
            "syslog": {
                "encrypted_password": "",
                "key": ""
            },
            "vsp": {
                "encrypted_password": "",
                "key": ""
            },
            "api_version": "1.0"
        }
    }

compensating_control = f"SecRule REQUEST_URI '/bookstore/Registration.jsp' 'id: {random.randint(10000, 10100)}, phase:2, drop, capture, t:none,t:urlDecode,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls, msg:'Cross Site Scripting(XSS) Attack Detected', logdata:'Matched Data: % found within %: %', tag:'custom-rule-attack-xss', tag:'OWASP_CRS/WEB_ATTACK/XSS', tag:'OWASP_TOP_10/A3', ctl:auditLogParts=+E, severity:'CRITICAL', setvar:'tx.msg=%', setvar:'tx.xss_score=+%', setvar:'tx.anomaly_score_pl1=+%',chain'\nSecRule ARGS_NAMES 'first_name' 'chain'\nSecRule ARGS '@detectXSS'\n\n\nSecRule REQUEST_URI '/bookstore/Login.jsp' 'id: 10002, phase:2, drop, capture, t:none,t:urlDecode,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls, msg:'Cross Site Scripting(XSS) Attack Detected', logdata:'Matched Data: % found within %: %', tag:'custom-rule-attack-xss', tag:'OWASP_CRS/WEB_ATTACK/XSS', tag:'OWASP_TOP_10/A3', ctl:auditLogParts=+E, severity:'CRITICAL', setvar:'tx.msg=%', setvar:'tx.xss_score=+%', setvar:'tx.anomaly_score_pl1=+%',chain'\nSecRule ARGS_NAMES 'Login' 'chain'\nSecRule ARGS '@detectXSS'\n\n\n"