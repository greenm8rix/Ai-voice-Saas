def get_subscription_tier(subscription_tier):
    if subscription_tier == "FREE" or subscription_tier == None:
        max_character_count = 1200
        max_downloads = 1

    if subscription_tier == "Personal":
        max_character_count = 1200
        max_downloads = 3333333
    if subscription_tier == "ContentCreator":
        max_character_count = 1000
        max_downloads = 35
    if subscription_tier == "God":
        max_character_count = 10000
        max_downloads = 33333333333

    return max_character_count, max_downloads


def get_subscription_tier_content(subscription_tier):
    if subscription_tier == "FREE" or subscription_tier == None:
        max_downloads = 5
    if subscription_tier == "Personal":
        max_downloads = 20
    if subscription_tier == "ContentCreator":
        max_downloads = 60
    if subscription_tier == "Personals":
        max_downloads = 20
    if subscription_tier == "ContentCreators":
        max_downloads = 60
    if subscription_tier == "God":
        max_character_count = 10000
        max_downloads = 33333333333

    return max_downloads
