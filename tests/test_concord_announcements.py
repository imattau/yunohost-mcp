from yunohost_mcp.concord_announcements import build_announcement_draft, prepare_announcement


def test_draft_uses_catalogue_metadata_and_is_deterministic():
    publication = {
        "app_id": "ditto",
        "version": "1.2~ynh1",
        "naddr": "naddr1example",
        "event": {"id": "a" * 64},
    }

    first = build_announcement_draft("https://example.org/ditto_ynh.git", publication)
    second = build_announcement_draft("https://example.org/ditto_ynh.git", publication)

    assert first == second
    assert first.repository_name == "ditto_ynh"
    assert first.text == "Published ditto 1.2~ynh1 to the YunoHost catalogue: naddr1example"
    assert first.idempotency_key.startswith("catalogue:")


def test_draft_falls_back_to_event_tags_and_without_naddr():
    draft = build_announcement_draft(
        "/srv/ditto_ynh",
        {"event": {"tags": [["d", "ditto"], ["version", "2.0~ynh1"]]}},
    )

    assert draft.app_id == "ditto"
    assert draft.version == "2.0~ynh1"
    assert draft.catalogue_reference is None
    assert draft.text == "Published ditto 2.0~ynh1 to the YunoHost catalogue"


def test_preparation_routes_by_repository_channel():
    prepared = prepare_announcement(
        "https://example.org/ditto_ynh.git",
        {"app_id": "ditto", "version": "1.2~ynh1", "naddr": "naddr1example"},
        {"channels": [{"channel_id": "channel-42", "name": "ditto_ynh"}]},
    )

    assert prepared.status == "ready"
    assert prepared.channel is not None
    assert prepared.channel.channel_id == "channel-42"


def test_preparation_reports_non_blocking_routing_warnings():
    publication = {"app_id": "ditto", "version": "1.2~ynh1"}
    missing = prepare_announcement("/srv/ditto_ynh", publication, {"channels": []})
    ambiguous = prepare_announcement(
        "/srv/ditto_ynh",
        publication,
        {"channels": [{"id": "one", "name": "ditto_ynh"}, {"id": "two", "name": "ditto_ynh"}]},
    )

    assert missing.status == "no_matching_channel"
    assert missing.channel is None
    assert ambiguous.status == "ambiguous_channel"
    assert ambiguous.channel is None
