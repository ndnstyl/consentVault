# Contract coverage map: records, confirmations, setup

Contracts: the cloud contracts for records, confirmations and setup, with the
amendments in `proof-export.md`, `capture.md`, `members.md`, `admin.md`, `billing.md`, `auth.md`.
Run: `pytest -m contract_pending tests/records tests/confirmations tests/setup`. The default run excludes them
(`addopts` in `pyproject.toml`, plus a collection hook in `tests/contract_world/fixtures.py` that survives a script's own `-m`).
Seams are those of confirmations.md sections 12 to 14 and records.md Testability. One mounting point is assumed (the contract names none): `AdminApp(confirmations=..., evidence_store=...)`, built once in `tests/contract_world/world.py` for every world. Failed reads use the named switch `consentvault.testing.fail_reads` (needs CONSENTVAULT_TEST_SEAMS=1, set in `fixtures.py`).
Status of every test today: red for "not built yet" (404 no such endpoint, missing module, missing table or column).

Legend: T = tested (file::test name stem). N = not testable black-box, with the reason.

## records.md
| Statement | Result |
|---|---|
| s1 one record per contact; email plus phone is two; subject_fp link and linked_record_count | T test_list::test_a_person_who_gave_an_email_and_a_phone_is_two_records_that_link |
| s1 name and company only in record_display, never in event, evidence or chain; developer never sees them | T test_capture_display (no name in event/evidence), test_list::test_a_developer_gets_fingerprints_only |
| s1 name/company deleted on erasure; unreadable on offboarding | T test_erasure::test_erasing_a_contact...; offboarding key destruction: N (needs custody destruction clock, covered by existing erasure suite pattern) |
| s1 never a filter, sort key or search term | T test_list::test_a_name_is_never_a_filter..., test_a_contact_point_is_never_a_filter |
| s1 record_id random UUID, survives erasure | T test_list::test_a_record_id_is_a_random_uuid..., test_erasure |
| s1 captured again after erasure: new record, nothing carried but the stop | T test_erasure::test_a_capture_after_erasure_mints_a_new_record... |
| s2 record object fields, masks, fp_hint, states, channels counts/purposes | T test_list (shape, email mask, channels) |
| s2 status mapping (stop row, consent, no record); record_incomplete absent | T test_list (stop, record_incomplete refused) |
| s3 every filter, sort, paging, cursor expiry, total, partial, masks from index, one key use per page | T test_list (all params), test_a_cursor_expires..., test_the_list_reads_masks... |
| s3 total null when the count cannot be read | T test_list::test_a_failed_total_read_is_null_never_zero (failed-reads switch records.total) |
| s3 audit records.listed before answer; 503 audit_unavailable returns no rows; person_shown ids | T test_list (three audit tests) |
| s3 errors list (validation_failed, invalid_cursor, UnknownPurposeError, invalid_channel, not_found, role) | T test_list, test_roles_isolation_proof |
| s3 service_unavailable | T test_data_layer::test_a_database_outage_answers_service_unavailable |
| s4 summary totals, series incl. zero days, tz, 400-day cap, by_channel rule, filters, not audited, counts only | T test_summary |
| s4 partial names null fields | T test_summary::test_summary_counts_are_null_and_named_in_partial... |
| s4 default window (last 30 days in tz, 30 buckets), call total (voice plus artificial voice, each record once, own failed-read switch), s6 reveal returns revealed_at from its audit row (ruled 2026-10-31) | T test_portal_rulings (tests/records) |
| confirmations s2/s4/s5/s12 ruled 2026-10-31: names on rule and send rows, template list shape, link-host answer with cname_target and verified_at, four fixed texts with version; admin s2/s3 viewer reads names only | T test_portal_rulings (tests/confirmations), test_viewer_names (tests/admin) |
| s5 search exact, normalised, audited, invalid_contact, shared bucket | T test_search_reveal |
| s6 reveal volume alarm (1,000 per member per hour, 5,000 per org per day, one open, no contact points, alarm row only and no email) | T test_search_reveal (mailer sent list unchanged) |
| s6 reveal order (requested row, unwrap, revealed row), both audit failures, erased/key_unavailable causes, limits, 200 ids | T test_search_reveal |
| s6 rate limit 30 per member per 10 minutes shared with search, Retry-After | T test_search_and_reveal_share_one_bucket... |
| s7 one build at a time (409 export_in_progress), build held in building | T test_exports (switch consentvault.testing.hold_steps "records.export.build" and run_export_builds) |
| s7 export: forms, include_person defaults and refusal, reason for full, zip contents, README text, manifest, sha256, formula prefix | T test_exports |
| s7 formula guard: = + - @ tab, carriage return prefixed; exact E.164 exempt; +1555555014a prefixed | T test_exports |
| s7 export audit rows and ids, 24 h expiry, one-use 15 minute link, new link, failure cleanup, suspended, ceiling | T test_exports (ceiling via consentvault.testing.overrides records.export_max_rows) |
| s7 link 15 minutes by the AdminApp clock, 410 export_link_expired / export_link_used, expired status and 410 export_expired | T test_exports |
| s7 stored in the evidence store at records-exports/<id>, encrypted | T test_exports::test_the_file_is_stored_encrypted... (assumes the evidence_store mounting keyword) |
| s8 tables, columns, row security, function properties, scopes, rebuild, confirmation writer, display key, aad binding, mask once | T test_data_layer |
| s8 display key cache | withdrawn by the contract; no test |
| s8 key rotation re-wraps org_display_key; offboarding makes names unreadable | N here by contract: tested in tests/providers/test_key_rotation.py and the offboarding suite; CENSUS_KINDS is T here |
| s9 P1 parse_capture, canonical bytes, bad display refused, received bytes kept | T test_capture_display |
| s9 R1 records written in the event transaction; failure rolls back | T test_capture_display, test_data_layer |
| s9 security manifest rebuilt and --check passes | T test_the_security_manifest_lists...; the --check run itself is the existing checkpoint stage |
| s9 migration ships with a down file | T test_data_layer::test_each_migration_ships... |
| proof-export amendment: record_id, masked contact, person, exactly one key, erased record found true | T test_roles_isolation_proof, test_erasure |
| members amendment: actions listed, detail never holds personal data | T test_roles_isolation_proof |
| auth: roles per route, no session = unauthenticated | T test_roles_isolation_proof |
| isolation: second organization sees nothing | T test_roles_isolation_proof, test_summary, test_data_layer |

## confirmations.md
| Statement | Result |
|---|---|
| s1 providers, Twilio and Telnyx, SES/Postmark; provider_not_supported | T test_configuration (Twilio, SES); Telnyx is out of scope and tested as provider_not_supported |
| s1 two Twilio secrets, sealed, never returned, auth token never used to call | T test_configuration |
| s1 connect steps, awaiting_test_reply, test reply verifies, no record made | T test_configuration |
| s1 keyword reply question, provider_replies all true or false | T test_configuration, test_inbound |
| s1 email sender_not_verified; provider_unreachable; provider_refused | T test_configuration (provider_refused: N, no trigger named for the fake) |
| s1 disconnect: inbound_still_pointed_here, unreachable, rules off, queued sends skipped, 30 day inbound window | T test_configuration |
| s1 auth token kept 30 days only for signatures | T test_configuration::test_the_twilio_auth_token_is_kept_30_days... (day 29 present, day 31 null) |
| s2 settings shape, versions, sender-only PUT, counts null not 0, delivery_reports stale | T test_configuration, test_sender (stale) |
| s2 counts null when unreadable | T test_configuration (timeout setting) |
| s2 link host set/verify/re-check hourly/failing/skip | T test_configuration |
| s3 registration mark, both boxes, errors, withdraw, stale on fixed-text change | T test_configuration (FIXED_TEXT_VERSION in confirm/texts.py, fixed_text_version in settings) |
| s4 rule fields, defaults, ranges, prerequisites, not_found, roles, audit, no backfill | T test_configuration, test_sender |
| s5 intent in the event transaction, unique key, duplicate does nothing | T test_sender |
| s5 SKIP LOCKED claim and advisory lock; duplicate-send lock | T test_sender::test_two_workers_racing... |
| s5 checks 1 to 10, each skip by name, order | T test_sender (parametrised); check 7 link_host_failing T in test_configuration |
| s5 quiet hours texts only (Mon-Sat 9-8, Sun noon-8, zone from area code, unknown zone, never delayed); email unaffected | T test_sender |
| s5 per-organization hourly cap (9a), org_hourly_cap, send_cap_reached, per channel, audited | T test_sender |
| s5 retries at offsets from the first attempt, jitter 0 and 0.2, dead_cause, re-check on retry, dead, key_unavailable, failed on refusal, 21610 records stop | T test_sender |
| s5 status change updates records list | T test_sender |
| s6 text and email fixed text, headers, preview | T test_configuration, test_sender |
| s6 wording page /c/r/{token}: content, never contact, host binding | T test_inbound |
| s7 contact_log row per accepted message, C4 shape, no row for unknown number, billing count | T test_sender |
| s7 inbound stored encrypted, fields, 30 day purge for no-match | T test_inbound, test_sender |
| s7 classification table and examples | T test_inbound (parametrised) |
| s7 stop event shape; admin-marked stop (written); provider refusal stop; pushed to systems | T test_inbound, test_sender |
| s7 email stop page: buttons, scopes, method checkbox, repeat, one-click, unrecordable message | T test_inbound |
| s7 START: grant shape, release rule met, refused cases, reply texts, no-stop and no-grant cases, C2 | T test_inbound |
| s7 our replies table: provider_replied, account, org status, registration; HELP once per hour; opt-out 5 minutes dead and alarm | T test_inbound |
| s7 unread 24 hours alarm; counts | T test_inbound |
| s7 a reply is never read by a model | T test_sender (no model client imported; a source scan, weak by nature) |
| s7 STOP scope across the organization's own channels only | T test_inbound (default four), test_sender (organization with only sms and email) |
| s8 sends and replies lists: filters, fields, masks, text for A and V only, audit | T test_sender, test_inbound |
| s9 check 0 body over 16 KB: 413 inbound_too_large, counted, nothing stored | T test_inbound |
| s9 check 1 signature over stored URL, forged forwarded headers, 401, failure count, alarm at 5 in 10 minutes | T test_inbound (alarm read from settings alarms) |
| s9 check 2 number mismatch 403, counted, records nothing | T test_inbound |
| s9 check 3 message id seen once (200, no event, no reply, audit inbound_replayed, long retention, unique per org) | T test_inbound |
| s9 check 4 Telnyx statements | N by contract: Telnyx is out of scope; no statements exist. provider telnyx refused is T test_configuration |
| s9 503 when unrecordable and the retry is not a replay | T test_inbound |
| s10 C2, C3, C4, R1; migrations with down | T C2/C4/R1 above; C3 sealing: N, contract says "recorded, never sealed" until it lands (proof item sealed false is T) |
| s10 admin.md: capture_verified credential hidden from the portal | N here by contract: tested in the admin suite |
| s11 error names and audit actions | T test_configuration (audit list), others named where raised |
| auth: roles on every confirmations route | T test_configuration, test_inbound |
| isolation: second organization sees nothing | T test_inbound |

## setup.md
| Statement | Result |
|---|---|
| GET shape, eight steps in order, required flags, roles, current_step, complete | T test_setup |
| done derived from each fact (brand, source, wording, credential, first event, policy, system, confirmations rule) | T test_setup (confirmations rule: needs the confirmations build; red until then) |
| blocked: org_suspended; needs:wording | T test_setup |
| partial and null status when a fact cannot be read | T test_setup (timeout setting) |
| status precedence done over skipped over blocked over to_do, skipped_by kept | T test_setup |
| skip/unskip: only system and confirmations, done cannot be skipped, who/when, reason, audit, step_not_skippable | T test_setup |
| roles incl. compliance viewer read-only and developer system only | T test_setup |
| table setup_step_skip, row security, down file; done never stored | T test_setup |
| audit actions listed | T test_setup |
| isolation | T test_setup |
| the /setup page refusal for a compliance viewer | N: portal route, not API |

## Statements still not testable, with the reason
- Template that drops a fixed part: the contract removed the error; the preview test asserts an unknown key is validation_failed.
- confirmations s1 `provider_refused` (`fields.provider_code`) on connect: no fake outcome is named for connect.
- records s2 offboarding and rotation (other suites, by contract). Unnamed in the contract and assumed or open: the admin alert email for the reveal alarm, how to hold an export in `building`, and a template that drops a fixed part.
- C3 contact log sealing (not built by design); the portal `/setup` refusal page; the hidden capture_verified credential (admin suite).

## Threat-model cases and the phone region rule
| Statement | Result |
|---|---|
| records.md phone region: default US, national format, GB organization, + ignores region, 555-01 invalid, confirmations:test same rule | T test_search_reveal, test_sender (organization created with default_region: assumed operator body key `default_region`) |
| LC-T3 injection strings in every filter, summary tz and search; forged and foreign cursors | T test_list |
| LC-I9 names returned as plain JSON, unaltered (rendering half is the portal's) | T test_list (Content-Type is checked only if the app layer sets it) |
| LC-I4 provider error text with a number or email scrubbed from logs, alarms, lists, audit | T test_sender (error text set on ProviderError args) |
| LC-D5 unrelated contacts do not wait on a slow send | T test_sender (two worker threads) |
| LC-E5 START or YES from a different number releases nothing | T test_inbound |
| back-dated and imported grants skip `late`; none or fresh sends | T test_sender |

## Round three additions
| Statement | Result |
|---|---|
| LC-I3 isolation across records, confirmations, setup, public pages: identical answers for a foreign id and an unheld id | T isolation/test_records_confirmations_isolation.py (a new file beside test_endpoints.py, which covers the machine API) |
| LC-I4 log scrub across the whole confirmation flow | T tests/test_log_scrub_confirmations.py (a new file beside test_log_scrub.py) |
| RFC 8058 one-click stop (POST body List-Unsubscribe=One-Click) records an email-only stop | T test_inbound |
| our_reply on the replies list: sent, provider_replied | T test_inbound |
| setup policy step approved with accepted true and the attestation digest | T test_setup |
| Armed world: the rules are on before the test's first grant; sends assertions filter channel sms (one intent per enabled rule) | T test_sender |
| One clock for the sender service and the admin app | T build_stack; pin requested from the designer |

## Rows added in round seven
| Statement | Result |
|---|---|
| s5 hourly cap per organization and channel (9a), default 500, 1..10000, audited, one alarm | T test_sender::test_the_organization_hourly_cap_skips_the_excess_raises_one_alarm_and_is_audited, test_the_cap_is_per_channel_so_a_text_cap_never_stops_email |
| s5 Account failing: 4 refusals leave connected, 5 consecutive pause + one alarm + next send skipped without a call, passing :check resumes | T test_sender (three tests, ProviderError kind account) |
| s7 START: only the whole message (START, UNSTOP, YES in any case) lifts; yes please, Start., START START, start now go to read | T test_inbound |
| s7 C2 with CONSENTVAULT_RELEASE_REQUIRE_NO_CONTACT_SINCE_STOP on | T test_inbound::test_start_lifts_a_stop_even_after_our_own_opt_out_reply (a non-confirmations contact since the stop refusing START: N, needs a contact_log row writer in the harness) |
| s7 contact_log contacted_at by the injected clock, recorded_at by the database; billing counts on the clock's date | T test_sender |

## Per-test contract line
Every test names the contract it encodes in its docstring; this table is generated from those docstrings (one row per test function; a parametrised function runs several cases). A test whose docstring names no contract line is not allowed.

| File | Test | Contract line |
|---|---|---|
| confirmations/test_configuration.py | test_connecting_a_twilio_account_answers_the_inbound_address_and_waits_for_a_test_reply | confirmations.md section 1 |
| confirmations/test_configuration.py | test_the_admins_yes_means_all_three_provider_replies_are_suppressed | confirmations.md section 1 |
| confirmations/test_configuration.py | test_secrets_are_sealed_under_the_org_key_and_the_auth_token_is_never_used_to_call_twilio | confirmations.md section 1 |
| confirmations/test_configuration.py | test_a_text_account_is_connected_only_after_a_signed_test_reply_arrives | confirmations.md section 1 |
| confirmations/test_configuration.py | test_account_input_refusals | confirmations.md section 1 |
| confirmations/test_configuration.py | test_check_reads_the_account_and_sends_no_message | confirmations.md endpoint table |
| confirmations/test_configuration.py | test_disconnect_is_refused_while_the_inbound_webhook_still_points_here | confirmations.md section 1 |
| confirmations/test_configuration.py | test_disconnect_turns_rules_off_skips_queued_sends_and_keeps_accepting_replies_for_30_days | confirmations.md section 1 |
| confirmations/test_configuration.py | test_a_disconnect_stays_a_role_matrix_a_only_and_connect_admits_a_developer | confirmations.md endpoint table |
| confirmations/test_configuration.py | test_account_changes_are_paused_while_suspended | confirmations.md section 1 errors |
| confirmations/test_configuration.py | test_settings_shape_and_a_put_makes_a_new_version_and_changes_the_sender_only | confirmations.md section 2 |
| confirmations/test_configuration.py | test_settings_counts_are_null_when_they_cannot_be_read_never_zero | confirmations.md section 2 and 13 |
| confirmations/test_configuration.py | test_settings_roles | confirmations.md endpoint table |
| confirmations/test_configuration.py | test_link_host_is_set_then_verified_against_dns | confirmations.md section 2 |
| confirmations/test_configuration.py | test_a_host_that_stops_resolving_fails_after_two_hourly_checks_and_sends_are_skipped | confirmations.md section 2 |
| confirmations/test_configuration.py | test_texting_registration_is_marked_with_who_when_and_the_fixed_text_version | confirmations.md section 3 |
| confirmations/test_configuration.py | test_withdrawing_registration_turns_every_text_rule_off_and_skips_queued_texts | confirmations.md section 3 |
| confirmations/test_configuration.py | test_a_changed_fixed_text_makes_the_mark_stale_and_turns_text_rules_off | confirmations.md section 3 and 13 |
| confirmations/test_configuration.py | test_the_twilio_auth_token_is_kept_30_days_after_a_disconnect_then_nulled_by_the_purge | confirmations.md section 13 |
| confirmations/test_configuration.py | test_the_providers_answer_can_be_changed_after_connecting | confirmations.md section 12 |
| confirmations/test_configuration.py | test_unknown_keys_in_a_configuration_body_are_refused_naming_the_key | confirmations.md section 12 |
| confirmations/test_configuration.py | test_telnyx_is_refused_with_provider_not_supported | confirmations.md section 1 |
| confirmations/test_configuration.py | test_rules_list_one_per_source_and_channel_with_defaults | confirmations.md section 4 |
| confirmations/test_configuration.py | test_a_rule_turned_on_is_refused_with_the_first_failing_prerequisite_in_the_pinned_order | confirmations.md section 4 |
| confirmations/test_configuration.py | test_the_email_rule_needs_an_account_then_sender_then_host_and_no_texting_prerequisites | confirmations.md section 4 |
| confirmations/test_configuration.py | test_a_role_beats_a_body_error_and_a_body_error_beats_a_missing_object | confirmations.md section 4 |
| confirmations/test_configuration.py | test_rule_input_rules_and_roles_and_audit | confirmations.md section 4 |
| confirmations/test_configuration.py | test_templates_are_versions_that_are_never_edited_in_place | confirmations.md sections 4 and 12 |
| confirmations/test_configuration.py | test_preview_renders_the_fixed_text_and_refuses_an_unknown_template_key | confirmations.md section 6 |
| confirmations/test_configuration.py | test_the_new_error_names_and_audit_actions_exist | confirmations.md section 11 |
| confirmations/test_configuration.py | test_a_test_message_goes_to_a_contact_the_admin_controls_and_is_audited | confirmations.md endpoint table |
| confirmations/test_inbound.py | test_a_signature_over_the_stored_url_is_accepted_even_with_a_forged_forwarded_host | confirmations.md section 9 check 1 |
| confirmations/test_inbound.py | test_a_request_signed_over_another_url_or_with_a_bad_signature_is_refused_and_counted | confirmations.md section 9 check 1 |
| confirmations/test_inbound.py | test_a_body_over_16_kb_is_refused_413_before_anything_is_stored_and_counted | confirmations.md section 9 check 0 |
| confirmations/test_inbound.py | test_an_unknown_inbound_key_is_refused | confirmations.md section 9 |
| confirmations/test_inbound.py | test_a_message_to_a_number_that_is_not_the_connected_number_is_refused_and_records_nothing | confirmations.md section 9 check 2 |
| confirmations/test_inbound.py | test_the_same_provider_message_id_twice_records_once_and_audits_the_replay | confirmations.md section 9 check 3 |
| confirmations/test_inbound.py | test_a_replay_months_later_is_still_refused_and_the_seen_key_is_per_organization | confirmations.md section 9 check 3 |
| confirmations/test_inbound.py | test_an_inbound_that_cannot_be_recorded_answers_503_and_the_retry_is_not_a_replay | confirmations.md section 9 |
| confirmations/test_inbound.py | test_replies_are_classified_by_the_core_classifier_and_mapped_to_an_action | confirmations.md section 7 |
| confirmations/test_inbound.py | test_a_start_that_is_not_the_whole_message_goes_to_read_and_lifts_nothing | confirmations.md section 7 |
| confirmations/test_inbound.py | test_a_whole_message_start_word_in_any_case_lifts_a_consumers_own_stop | confirmations.md section 7 |
| confirmations/test_inbound.py | test_a_stop_reply_is_one_revoke_across_sms_voice_and_artificial_voice_and_leaves_email | confirmations.md section 7 |
| confirmations/test_inbound.py | test_a_stop_is_pushed_to_connected_systems_like_any_stop | confirmations.md section 7 |
| confirmations/test_inbound.py | test_the_inbound_text_is_stored_encrypted_under_the_contact_key_or_the_org_key | confirmations.md section 7 |
| confirmations/test_inbound.py | test_reply_reads_show_text_to_admin_and_viewer_only_and_are_audited | confirmations.md section 8 |
| confirmations/test_inbound.py | test_an_admin_marks_a_reply_as_a_stop_with_method_written_or_not_a_stop_with_a_reason | confirmations.md section 7 |
| confirmations/test_inbound.py | test_an_unread_reply_for_24_hours_raises_the_alarm_and_counts_show_in_settings | confirmations.md section 2 and 7 |
| confirmations/test_inbound.py | test_start_after_a_stop_is_a_keyword_grant_naming_texts_only_and_lifts_the_stop | confirmations.md section 7 |
| confirmations/test_inbound.py | test_start_with_no_stop_on_record_changes_nothing_and_sends_no_reply | confirmations.md section 7 |
| confirmations/test_inbound.py | test_start_after_a_stop_with_no_earlier_grant_is_a_reply_only_with_the_refused_text | confirmations.md section 7 |
| confirmations/test_inbound.py | test_start_from_a_number_with_no_record_is_a_reply_only | confirmations.md section 7 and 10 |
| confirmations/test_inbound.py | test_start_is_refused_when_the_stop_was_not_the_consumers_own | confirmations.md section 7 |
| confirmations/test_inbound.py | test_start_is_refused_when_the_wording_the_person_agreed_to_names_no_text | confirmations.md section 7 |
| confirmations/test_inbound.py | test_start_lifts_a_stop_even_after_our_own_opt_out_reply | confirmations.md section 7 |
| confirmations/test_inbound.py | test_our_replies_are_sent_per_the_table_and_suppressed_when_the_provider_replies_itself | confirmations.md section 7 |
| confirmations/test_inbound.py | test_help_is_answered_at_most_once_per_contact_per_hour | confirmations.md section 7 |
| confirmations/test_inbound.py | test_with_the_provider_replying_itself_none_of_our_three_replies_are_sent | confirmations.md sections 1 and 7 |
| confirmations/test_inbound.py | test_replies_follow_the_organization_status | confirmations.md section 7 table |
| confirmations/test_inbound.py | test_replies_are_not_sent_when_registration_is_not_marked_except_the_opt_out | confirmations.md section 7 table |
| confirmations/test_inbound.py | test_an_opt_out_reply_that_cannot_go_in_five_minutes_is_dead_and_alarms | confirmations.md section 7 |
| confirmations/test_inbound.py | test_reply_messages_are_contact_log_rows_with_their_own_outcomes | confirmations.md sections 7 and 10 |
| confirmations/test_inbound.py | test_the_wording_page_shows_the_agreed_wording_and_never_the_contact | confirmations.md section 6 |
| confirmations/test_inbound.py | test_the_email_stop_page_stops_email_or_everything_and_a_repeat_records_nothing | confirmations.md section 7 |
| confirmations/test_inbound.py | test_a_stop_page_that_cannot_record_says_so_and_keeps_the_buttons | confirmations.md section 7 |
| confirmations/test_inbound.py | test_a_second_organization_sees_none_of_the_confirmations | auth.md |
| confirmations/test_inbound.py | test_a_start_from_a_different_number_never_lifts_another_numbers_stop | LC-E5 |
| confirmations/test_sender.py | test_a_grant_inserts_one_intent_in_the_events_transaction_and_a_duplicate_does_nothing | confirmations.md section 5 |
| confirmations/test_sender.py | test_only_enabled_rules_on_the_events_source_make_intents_and_older_grants_never_send | confirmations.md section 4 and 5 |
| confirmations/test_sender.py | test_a_text_is_sent_from_the_customers_number_with_the_fixed_text_and_a_status_callback | confirmations.md section 1 and 6 |
| confirmations/test_sender.py | test_an_email_has_the_fixed_parts_the_exact_wording_and_the_one_click_headers | confirmations.md section 6 |
| confirmations/test_sender.py | test_text_quiet_hours_monday_to_saturday_run_9_am_to_8_pm_local | confirmations.md section 5 item 5 |
| confirmations/test_sender.py | test_sunday_texts_start_at_noon_local | confirmations.md section 5 item 5 |
| confirmations/test_sender.py | test_sunday_texts_end_at_8_pm_exclusive | confirmations.md section 5 item 5 |
| confirmations/test_sender.py | test_the_fixed_text_version_is_read_at_send_time | confirmations.md sections 3 and 13 |
| confirmations/test_sender.py | test_the_zone_comes_from_the_area_code_and_an_unknown_zone_skips_the_text | confirmations.md section 5 item 5 |
| confirmations/test_sender.py | test_email_has_no_sending_hours_and_needs_no_phone_or_zone | confirmations.md section 5 item 5 |
| confirmations/test_sender.py | test_each_skip_is_recorded_by_name_and_nothing_is_sent | confirmations.md section 5 items 1, 2, 3, 4, 6, 8, 9 |
| confirmations/test_sender.py | test_a_text_to_an_email_record_is_never_sent | confirmations.md section 5 item 2 |
| confirmations/test_sender.py | test_back_dated_grants_never_send_and_a_grant_with_none_or_a_fresh_one_does | confirmations.md section 5 item 4 |
| confirmations/test_sender.py | test_past_due_still_sends_but_offboarding_and_closed_do_not | confirmations.md section 5 item 8 |
| confirmations/test_sender.py | test_a_trial_event_sends_when_the_rule_says_so_and_skips_test_event_when_it_does_not | confirmations.md section 4 and 5 item 9 |
| confirmations/test_sender.py | test_a_second_confirmation_inside_the_dedupe_window_is_skipped_and_one_after_it_is_sent | confirmations.md section 5 item 6 |
| confirmations/test_sender.py | test_two_workers_racing_on_one_contact_send_exactly_one_message | confirmations.md section 5 |
| confirmations/test_sender.py | test_a_retryable_error_is_retried_at_offsets_from_the_first_attempt_then_dead | confirmations.md section 5 retries |
| confirmations/test_sender.py | test_the_retry_delay_stretches_by_the_injected_jitter_at_most_20_percent | confirmations.md sections 5 and 13 |
| confirmations/test_sender.py | test_a_retry_that_lands_after_a_stop_or_in_quiet_hours_ends_as_that_skip | confirmations.md section 5 retries |
| confirmations/test_sender.py | test_a_key_that_will_not_open_is_retried_then_dead_with_cause_key_unavailable_and_nothing_is_sent | confirmations.md section 5 item 10 |
| confirmations/test_sender.py | test_a_provider_refusal_ends_the_send_failed_and_an_opt_out_refusal_records_a_stop | confirmations.md section 5 and 7 |
| confirmations/test_sender.py | test_status_changes_update_the_record_list_and_a_delivery_report_marks_delivered | confirmations.md section 5 |
| confirmations/test_sender.py | test_a_sent_message_is_one_contact_log_row_encrypted_and_retries_add_none | confirmations.md section 7 and 10 |
| confirmations/test_sender.py | test_the_proof_lists_the_confirmation_as_recorded_and_not_sealed | proof-export.md amendment |
| confirmations/test_sender.py | test_each_accepted_message_counts_as_one_billable_event_and_skips_and_retries_do_not | billing.md usage reporting |
| confirmations/test_sender.py | test_a_reply_from_a_number_with_no_record_is_kept_under_the_org_key_and_not_billed | confirmations.md section 10 |
| confirmations/test_sender.py | test_the_sends_list_filters_masks_and_is_audited | confirmations.md section 8 |
| confirmations/test_sender.py | test_nothing_in_the_confirmations_code_reads_a_reply_with_a_model | confirmations.md section 7 |
| confirmations/test_sender.py | test_provider_error_text_with_a_contact_in_it_never_reaches_logs_alerts_or_lists | LC-I4 and confirmations.md section 7 |
| confirmations/test_sender.py | test_a_slow_send_to_one_contact_never_makes_an_unrelated_contact_wait | LC-D5 and confirmations.md section 5 |
| confirmations/test_sender.py | test_the_organization_hourly_cap_skips_the_excess_raises_one_alarm_and_is_audited | confirmations.md section 5 item 9a |
| confirmations/test_sender.py | test_the_cap_is_per_channel_so_a_text_cap_never_stops_email | confirmations.md section 5 item 9a |
| confirmations/test_sender.py | test_a_test_message_reads_a_national_number_with_the_default_region | records.md phone region rule |
| confirmations/test_sender.py | test_a_21610_refusal_opens_the_provider_refusal_stop_alarm_and_counts_it | confirmations.md sections 2, 5 and 13 |
| confirmations/test_sender.py | test_four_account_level_refusals_in_a_row_raise_nothing_and_a_success_resets_the_count | confirmations.md section 5 Account failing |
| confirmations/test_sender.py | test_five_consecutive_account_level_refusals_pause_the_account_and_skip_the_next_send_without_a_call | confirmations.md section 5 Account failing |
| confirmations/test_sender.py | test_a_passing_account_check_resumes_sending_and_clears_the_alarm | confirmations.md section 5 Account failing |
| confirmations/test_sender.py | test_a_check_against_an_unreachable_provider_answers_provider_unreachable_and_changes_nothing | confirmations.md section 1 errors |
| confirmations/test_sender.py | test_no_retry_is_attempted_later_than_120_minutes_after_the_first | confirmations.md section 5 retries |
| confirmations/test_sender.py | test_a_delivery_report_posted_to_another_organizations_inbound_address_changes_nothing | LC-S4 |
| confirmations/test_sender.py | test_an_organization_without_voice_gets_a_stop_naming_only_the_channels_it_has | confirmations.md section 7 and 14 |
| isolation/test_records_confirmations_isolation.py | test_search_answers_the_same_for_a_contact_only_a_holds_and_one_nobody_holds | records.md section 5 |
| isolation/test_records_confirmations_isolation.py | test_reveal_proof_and_export_answer_the_same_for_a_foreign_record_id_and_a_random_one | records.md section 6, 7 and proof-export.md amendment |
| isolation/test_records_confirmations_isolation.py | test_every_list_of_b_is_empty_of_a | auth.md |
| isolation/test_records_confirmations_isolation.py | test_b_cannot_mark_a_reply_or_set_a_rule_for_a_source_or_account_of_a | LC-E3 and LC-I3 |
| isolation/test_records_confirmations_isolation.py | test_b_cannot_call_a_public_stop_or_wording_page_with_a_token_of_a_on_its_own_host | confirmations.md section 6 and 7 |
| records/test_capture_display.py | test_parse_capture_removes_display_before_the_unknown_field_check | records.md section 9 |
| records/test_capture_display.py | test_with_display_the_body_is_the_canonical_json_of_the_rest | records.md section 9 |
| records/test_capture_display.py | test_without_display_the_received_bytes_are_kept_byte_for_byte | records.md section 9 |
| records/test_capture_display.py | test_display_is_an_object_of_name_and_company_strings_of_1_to_200_characters | records.md section 9 and capture.md |
| records/test_capture_display.py | test_display_at_the_limits_is_accepted | records.md section 9 |
| records/test_capture_display.py | test_a_capture_with_display_stores_no_name_in_the_event_the_evidence_or_the_chain | records.md section 9 and capture.md |
| records/test_capture_display.py | test_a_capture_with_a_bad_display_is_refused_and_records_nothing | capture.md amendment |
| records/test_capture_display.py | test_a_capture_without_display_stores_the_received_bytes | records.md section 9 |
| records/test_capture_display.py | test_a_capture_with_display_writes_the_display_row_under_the_display_key | capture.md amendment |
| records/test_capture_display.py | test_every_event_updates_the_records_tables_in_the_same_transaction | capture.md amendment and records.md section 9 |
| records/test_capture_display.py | test_a_records_failure_refuses_the_capture_as_service_unavailable | capture.md amendment |
| records/test_data_layer.py | test_the_four_tables_exist_with_the_contracted_columns_and_row_security | records.md section 8 |
| records/test_data_layer.py | test_a_second_organization_cannot_read_the_records_tables | records.md section 8 and the isolation rule |
| records/test_data_layer.py | test_owner_rights_functions_are_security_definer_with_a_pinned_search_path | records.md section 8 |
| records/test_data_layer.py | test_the_security_manifest_lists_the_new_functions_and_tables | records.md section 9 |
| records/test_data_layer.py | test_record_upsert_returns_the_active_record_and_refuses_another_organizations_event | records.md section 8 |
| records/test_data_layer.py | test_the_writers_take_only_capture_capture_verified_or_admin_scopes_and_rebuild_only_admin | records.md section 8 |
| records/test_data_layer.py | test_the_index_is_rebuilt_from_the_ledger_and_never_touches_record_or_display | records.md section 8 |
| records/test_data_layer.py | test_the_confirmation_writer_sets_last_confirmation_and_refuses_other_statuses | records.md section 8 |
| records/test_data_layer.py | test_a_failure_in_the_records_writers_rolls_the_event_back | records.md section 9 |
| records/test_data_layer.py | test_creating_an_organization_makes_a_display_key_wrapped_by_the_org_key | records.md section 8 and admin.md amendment |
| records/test_data_layer.py | test_the_key_adapter_gives_display_keys_and_the_rotation_census_covers_them | records.md section 8 |
| records/test_data_layer.py | test_a_stored_name_is_ciphertext_bound_to_its_org_record_and_column | records.md section 8 |
| records/test_data_layer.py | test_the_mask_is_written_once_on_the_first_event_and_is_ciphertext | records.md section 8 |
| records/test_data_layer.py | test_each_migration_ships_with_a_down_that_removes_its_tables | records.md section 9 |
| records/test_data_layer.py | test_a_database_outage_answers_service_unavailable | records.md Testability |
| records/test_erasure.py | test_erasing_a_contact_marks_the_record_erased_and_keeps_its_row | records.md section 1 and 8 |
| records/test_erasure.py | test_a_capture_after_erasure_mints_a_new_record_and_carries_nothing_over_but_the_stop | records.md section 1 |
| records/test_erasure.py | test_the_record_row_is_never_deleted_and_one_active_record_per_fingerprint | records.md section 8 |
| records/test_erasure.py | test_an_erased_records_stop_is_still_listed_through_the_proof | proof-export.md amendment |
| records/test_exports.py | test_an_export_builds_a_zip_with_the_csv_manifest_and_readme | records.md section 7 |
| records/test_exports.py | test_the_three_contact_forms_and_the_person_default | records.md section 7 |
| records/test_exports.py | test_a_fingerprint_export_with_names_and_a_full_export_without_a_reason_are_refused | records.md section 7 |
| records/test_exports.py | test_cells_that_start_with_a_formula_character_are_prefixed_except_an_exact_e164_number | records.md section 7 |
| records/test_exports.py | test_a_second_export_while_one_is_building_is_refused_and_a_new_one_starts_after | records.md section 7 |
| records/test_exports.py | test_an_export_takes_the_list_filters | records.md section 7 |
| records/test_exports.py | test_export_audit_rows_and_the_ids_they_carry | records.md section 7 |
| records/test_exports.py | test_a_download_link_is_good_once | records.md section 7 |
| records/test_exports.py | test_a_link_is_good_for_15_minutes_and_a_new_one_can_be_minted_while_the_file_is_kept | records.md section 7 |
| records/test_exports.py | test_the_file_is_kept_24_hours_then_it_reads_expired_and_the_link_answers_410 | records.md section 7 |
| records/test_exports.py | test_the_file_is_stored_encrypted_under_the_org_key_in_the_evidence_store | records.md section 7 |
| records/test_exports.py | test_export_list_and_detail_shapes | records.md section 7 |
| records/test_exports.py | test_a_build_whose_built_audit_row_cannot_be_written_is_failed_and_the_file_deleted | records.md section 7 |
| records/test_exports.py | test_the_requested_audit_row_is_committed_before_the_build_starts | records.md section 7 |
| records/test_exports.py | test_an_export_is_paused_while_suspended | records.md section 7 |
| records/test_exports.py | test_export_roles | records.md section 7 and auth.md |
| records/test_exports.py | test_the_export_ceiling_is_250000_rows | records.md section 7 |
| records/test_list.py | test_a_listed_record_has_exactly_the_contract_fields | records.md section 2 |
| records/test_list.py | test_an_email_record_is_masked_with_its_first_letter | records.md section 2 |
| records/test_list.py | test_a_record_id_is_a_random_uuid_that_reveals_nothing_about_the_contact | records.md section 1 |
| records/test_list.py | test_a_person_who_gave_an_email_and_a_phone_is_two_records_that_link | records.md section 1 |
| records/test_list.py | test_the_same_contact_captured_twice_is_one_record_with_a_moving_last_event | records.md section 1 |
| records/test_list.py | test_every_channel_the_organization_has_appears_with_every_purpose | records.md section 2 |
| records/test_list.py | test_a_stop_on_every_purpose_reads_stop_on_record_for_the_cells_that_have_no_grant | records.md section 2 |
| records/test_list.py | test_record_incomplete_is_not_a_list_status | records.md section 2 and 3 |
| records/test_list.py | test_status_channel_purpose_stop_and_kind_filters | records.md section 3 |
| records/test_list.py | test_source_and_brand_filters_and_their_refusals | records.md section 3 |
| records/test_list.py | test_unknown_purpose_and_unknown_channel_are_named_errors | records.md section 3 |
| records/test_list.py | test_a_contact_point_is_never_a_filter | README section 1 |
| records/test_list.py | test_date_filters_pick_the_date_field_with_from_inclusive_and_to_exclusive | records.md section 3 |
| records/test_list.py | test_state_default_active_and_trial_filters | records.md section 3 |
| records/test_list.py | test_sort_orders_are_stable_with_ties_broken_by_record_id | records.md section 3 |
| records/test_list.py | test_paging_walks_every_record_once_forward_and_back_and_total_counts_all | records.md section 3 |
| records/test_list.py | test_a_cursor_expires_after_24_hours | README section 1 |
| records/test_list.py | test_the_list_reads_masks_from_the_index_with_one_key_use_per_page | records.md section 3 |
| records/test_list.py | test_a_display_key_failure_nulls_masks_and_names_but_never_hides_a_stop | records.md section 3 |
| records/test_list.py | test_person_name_and_company_are_the_latest_captured_and_each_can_be_absent | records.md section 2 |
| records/test_list.py | test_a_name_is_never_a_filter_sort_key_or_search_term | records.md section 1 |
| records/test_list.py | test_a_developer_gets_fingerprints_only_and_never_a_name_company_or_mask | records.md section 3 |
| records/test_list.py | test_a_list_call_writes_a_records_listed_audit_row_before_the_answer | records.md section 3 |
| records/test_list.py | test_a_developers_list_call_audits_an_empty_person_shown_list | records.md section 3 |
| records/test_list.py | test_when_the_audit_row_cannot_be_written_no_rows_are_returned | records.md section 3 |
| records/test_list.py | test_confirmation_filter_reads_the_last_confirmation_outcome | records.md section 3 |
| records/test_list.py | test_a_failed_total_read_is_null_never_zero | records.md section 3 |
| records/test_list.py | test_failed_mask_and_person_reads_null_those_fields_and_are_named_in_partial | records.md section 3 |
| records/test_list.py | test_a_later_send_replaces_an_earlier_skip_in_the_records_confirmation_column | records.md section 2 |
| records/test_list.py | test_injection_strings_are_inert_and_a_foreign_cursor_is_refused | LC-T3, records.md section 3 and README section 1 |
| records/test_list.py | test_names_come_back_as_plain_json_strings_unaltered | LC-I9 |
| records/test_roles_isolation_proof.py | test_every_records_route_admits_exactly_its_roles | records.md endpoint table and auth.md |
| records/test_roles_isolation_proof.py | test_every_records_route_needs_a_session | README section 1 and auth.md |
| records/test_roles_isolation_proof.py | test_a_second_organization_sees_nothing_and_cannot_reach_anothers_records | auth.md |
| records/test_roles_isolation_proof.py | test_the_same_contact_in_two_organizations_is_two_unrelated_records | records.md section 1 |
| records/test_roles_isolation_proof.py | test_proof_by_record_id_adds_the_masked_contact_and_the_person_and_never_the_full_contact | proof-export.md amendment |
| records/test_roles_isolation_proof.py | test_proof_and_export_accept_exactly_one_of_contact_or_record_id | proof-export.md amendment |
| records/test_roles_isolation_proof.py | test_proof_by_record_id_shows_a_developer_nothing_and_audits_as_proof_read | proof-export.md amendment |
| records/test_roles_isolation_proof.py | test_the_new_audit_actions_are_all_listed_for_the_filter_menu | members.md amendment |
| records/test_roles_isolation_proof.py | test_an_audit_detail_never_holds_a_contact_point_name_company_or_reply_text | members.md amendment |
| records/test_roles_isolation_proof.py | test_a_records_list_does_not_audit_a_viewer_reading_the_summary | records.md section 4 |
| records/test_search_reveal.py | test_search_finds_the_one_record_for_an_exact_contact_however_it_is_formatted | records.md section 5 |
| records/test_search_reveal.py | test_search_refuses_what_is_not_a_contact_point_and_partial_matches_cannot_exist | records.md section 5 |
| records/test_search_reveal.py | test_search_audits_found_or_not_with_a_fingerprint_hint_and_never_the_contact | records.md section 5 |
| records/test_search_reveal.py | test_search_and_reveal_share_one_bucket_of_30_calls_per_member_per_10_minutes | records.md section 5 and 6 |
| records/test_search_reveal.py | test_search_and_reveal_are_closed_to_a_developer | records.md section 5 and 6 |
| records/test_search_reveal.py | test_reveal_returns_full_contacts_with_the_audit_rows_in_order | records.md section 6 |
| records/test_search_reveal.py | test_a_failed_first_audit_row_means_nothing_is_unwrapped | records.md section 6 |
| records/test_search_reveal.py | test_a_failed_second_audit_row_discards_the_decrypted_values | records.md section 6 |
| records/test_search_reveal.py | test_an_erased_record_reveals_nothing_with_cause_erased | records.md section 6 |
| records/test_search_reveal.py | test_an_unavailable_contact_key_reveals_nothing_with_cause_key_unavailable | records.md section 6 |
| records/test_search_reveal.py | test_reveal_input_rules | records.md section 6 |
| records/test_search_reveal.py | test_reveal_of_up_to_200_records_in_one_call | records.md section 6 |
| records/test_search_reveal.py | test_one_member_passing_1000_distinct_records_in_an_hour_opens_exactly_one_alarm | records.md section 6 reveal volume alarm |
| records/test_search_reveal.py | test_repeat_reveals_of_the_same_records_never_open_the_alarm | records.md section 6 |
| records/test_search_reveal.py | test_the_organization_reveal_alarm_opens_past_5000_distinct_records_in_24_hours_across_members | records.md section 6 reveal volume alarm |
| records/test_search_reveal.py | test_a_national_number_is_read_with_the_organizations_default_region | records.md phone region rule |
| records/test_summary.py | test_summary_counts_totals_stops_and_new_records_in_range | records.md section 4 |
| records/test_summary.py | test_summary_series_lists_every_day_in_range_with_zero_days_as_zero | records.md section 4 |
| records/test_summary.py | test_summary_day_buckets_follow_the_requested_time_zone | records.md section 4 |
| records/test_summary.py | test_summary_series_span_is_at_most_400_days_and_bad_zone_is_refused | records.md section 4 |
| records/test_summary.py | test_summary_by_channel_counts_each_record_once_under_its_most_protective_status | records.md section 4 |
| records/test_summary.py | test_summary_takes_the_list_filters | records.md section 4 |
| records/test_summary.py | test_summary_is_counts_only_open_to_every_role_and_never_audited | records.md section 4 |
| records/test_summary.py | test_summary_of_one_organization_ignores_the_other | records.md section 4 and the isolation rule |
| records/test_summary.py | test_each_failed_summary_read_is_null_and_named_in_partial | records.md section 4 |
| setup/test_setup.py | test_get_setup_lists_the_eight_steps_in_order_with_the_contract_fields | setup.md GET /v1/setup |
| setup/test_setup.py | test_done_is_derived_from_the_facts_on_every_read | setup.md |
| setup/test_setup.py | test_first_event_and_wording_and_blocking | setup.md |
| setup/test_setup.py | test_first_event_is_done_by_a_recorded_event | setup.md |
| setup/test_setup.py | test_policy_step_is_done_by_an_approved_policy | setup.md |
| setup/test_setup.py | test_system_step_is_done_by_a_test_push_answered_2xx_and_confirmations_by_a_rule_that_is_on | setup.md |
| setup/test_setup.py | test_confirmations_step_is_done_by_a_rule_that_is_on_with_the_rule_as_evidence | setup.md |
| setup/test_setup.py | test_current_step_is_the_first_neither_done_nor_skipped_and_complete_needs_only_the_required_six | setup.md |
| setup/test_setup.py | test_skip_records_who_and_when_is_audited_and_unskip_returns_to_do | setup.md |
| setup/test_setup.py | test_only_system_and_confirmations_can_be_skipped_and_a_done_step_cannot | setup.md |
| setup/test_setup.py | test_a_done_optional_step_cannot_be_skipped | setup.md |
| setup/test_setup.py | test_roles_on_setup | setup.md and auth.md |
| setup/test_setup.py | test_a_suspended_organization_blocks_the_credential_and_system_steps | setup.md |
| setup/test_setup.py | test_skips_belong_to_their_organization | setup.md |
| setup/test_setup.py | test_setup_actions_are_listed_for_the_audit_filter | members.md amendment and setup.md |
| setup/test_setup.py | test_the_skip_table_stores_only_skips | setup.md migration |
| setup/test_setup.py | test_a_fact_that_cannot_be_read_is_null_and_named_in_partial | setup.md |
| setup/test_setup.py | test_done_beats_skipped_and_turning_the_rule_off_returns_to_skipped | setup.md status precedence |
| setup/test_setup.py | test_a_skipped_step_that_turns_blocked_reads_skipped_and_a_blocked_to_do_reads_blocked | setup.md status precedence |
| setup/test_setup.py | test_a_step_cannot_be_marked_done_by_the_caller | setup.md |
| test_log_scrub_confirmations.py | test_a_confirmation_flow_logs_no_personal_data_or_secret | confirmations.md section 1 |
