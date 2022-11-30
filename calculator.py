def get_subscription_tier(subscription_tier):
    if subscription_tier == "FREE" or subscription_tier == None:
        max_character_count = 10000
        max_downloads = 1
    if subscription_tier == "Personal":
        max_character_count = 3000
        max_downloads = 8
    if subscription_tier == "ContentCreator":
        max_character_count = 3000
        max_downloads = 30

    return max_character_count, max_downloads
