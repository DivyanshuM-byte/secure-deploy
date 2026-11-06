# Sample application containing fake Personally Identifiable Information (PII) for testing only
# All values are fictitious test fixtures.

# Fake Aadhaar with valid Verhoeff checksum
CUSTOMER_AADHAAR = "2345 6789 0124"

# Fake Indian mobile number
CUSTOMER_PHONE = "+91 9820123456"

# Fake customer contact email (non-dummy domain)
CUSTOMER_EMAIL = "compliance.officer@internal-corp.in"

# Fake Permanent Account Number (PAN) with valid 4th status char P (Individual)
COMPANY_PAN = "ABCPE1234F"

# Luhn-valid test credit card number (standard Visa test number)
TEST_CARD_NUMBER = "4111 1111 1111 1111"

# Production database URL containing a hardcoded password
DATABASE_CONNECTION_URL = "postgres://billing_service:ProdSecretDbPass987@internal-db.corp.net:5432/customers"
