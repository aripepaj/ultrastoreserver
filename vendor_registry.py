from utilis import load_partners, vendor_key

class VendorRegistry:
    def __init__(self, partners_path="partners.json"):
        self.data = load_partners(partners_path)

    def recipients_for(self, vendor_name: str):
        # normalize lookup
        key = vendor_key(vendor_name)
        for k, v in self.data.items():
            if vendor_key(k) == key:
                return v
        # fallback
        return self.data.get("Unknown", [])