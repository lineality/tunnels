// =============================================================================
// PART 10: TESTS (test mode only). unwrap/assert/indexing allowed here only.
// =============================================================================
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod pingpong_tunnel_tests {
    use super::*;

    /// Every variant with its permanent code number. Guards the APPEND-ONLY
    /// rule: renumbering any variant fails this test. When adding a variant,
    /// append it here too.
    const ERROR_CODE_TABLE_FOR_TESTS: [(TunnelError, u16); 63] = [
        (TunnelError::SocketBindFailed, 1),
        (TunnelError::SocketReadFailed, 3),
        (TunnelError::SocketWriteFailed, 4),
        (TunnelError::SocketCloneFailed, 5),
        (TunnelError::SocketSendIncomplete, 6),
        (TunnelError::UdpPacketTruncated, 10),
        (TunnelError::UdpTimestampStale, 11),
        (TunnelError::UdpReplayDetected, 12),
        (TunnelError::UdpChecksumMismatch, 13),
        (TunnelError::TerminalStdinReadFailed, 30),
        (TunnelError::TerminalStdoutWriteFailed, 31),
        (TunnelError::TerminalStdoutFlushFailed, 32),
        (TunnelError::NonceEntropyOpenFailed, 50),
        (TunnelError::NonceEntropyReadFailed, 51),
        (TunnelError::ClockBeforeUnixEpoch, 52),
        (TunnelError::ClockTimestampExceedsU32, 53),
        (TunnelError::ConfigInvalidPort, 100),
        (TunnelError::ConfigInvalidIp, 101),
        (TunnelError::ConfigInvalidArgs, 102),
        (TunnelError::ConfigInvalidToml, 103),
        (TunnelError::ConfigExePathFailed, 104),
        (TunnelError::ConfigNoPeersConfigured, 105),
        (TunnelError::ConfigValidationByteOutOfRange, 106),
        (TunnelError::ConfigSaltIndexOutOfRange, 107),
        (TunnelError::ConfigTomlKeyTooLong, 108),
        (TunnelError::ConfigU32ValueEmpty, 109),
        (TunnelError::ConfigU32ValueInvalidDigit, 110),
        (TunnelError::ConfigU32ValueOverflow, 111),
        (TunnelError::ConfigIpv4OctetEmpty, 112),
        (TunnelError::ConfigIpv4OctetLeadingZero, 113),
        (TunnelError::ConfigIpv4OctetOutOfRange, 114),
        (TunnelError::ConfigIpv4WrongOctetCount, 115),
        (TunnelError::ConfigIdentityNameEmpty, 116),
        (TunnelError::ConfigIdentityNameInvalidChar, 117),
        (TunnelError::ConfigIdentityNameTooLong, 118),
        (TunnelError::ConfigPathTooLong, 119),
        (TunnelError::ConfigPathNotUnicode, 120),
        (TunnelError::ConfigPathNotAbsolute, 121),
        (TunnelError::ConfigSaltSetAllZero, 122),
        (TunnelError::TomlEmptyKey, 130),
        (TunnelError::TomlOutputBufferZeroSized, 131),
        (TunnelError::TomlFileOpenFailed, 132),
        (TunnelError::TomlFileReadFailed, 133),
        (TunnelError::TomlFieldNotFound, 134),
        (TunnelError::TomlValueExceedsOutputBuffer, 135),
        (TunnelError::TomlValueUnterminatedAtEof, 136),
        (TunnelError::TomlSafetyBudgetExhausted, 137),
        (TunnelError::CliFlagMissingValue, 160),
        (TunnelError::CliValueTooLong, 161),
        (TunnelError::CliTooManyPeers, 162),
        (TunnelError::CliUnknownArgument, 163),
        (TunnelError::CliArgumentNotUnicode, 164),
        (TunnelError::CliDuplicateFlag, 165),
        (TunnelError::PromptInputTooLong, 180),
        (TunnelError::PromptInputNotUnicode, 181),
        (TunnelError::CryptoByte63Failed, 200),
        (TunnelError::CryptoByte62Failed, 201),
        (TunnelError::CryptoInvalidAscii, 202),
        (TunnelError::CryptoValidationByteMismatch, 203),
        (TunnelError::CryptoPaddingNotZero, 204),
        (TunnelError::CryptoTableNotPermutation, 205),
        (TunnelError::InternalThreadSpawnFailed, 300),
        (TunnelError::InternalErrorCodeRenderFailed, 400),
        // Sentinel duplicate of the last entry keeps the array length explicit
        // when appending: replace this line with the new variant.
        (TunnelError::InternalErrorCodeRenderFailed, 400),
        (TunnelError::InternalPortIntegrityCheckFailed, 401),
        (TunnelError::InternalIpv4IntegrityCheckFailed, 402),
        (TunnelError::InternalIdentityNameIntegrityCheckFailed, 403),
        (TunnelError::InternalValidationByteIntegrityCheckFailed, 404),
        (TunnelError::InternalSaltSetIntegrityCheckFailed, 405),
        (TunnelError::InternalPeerRosterIntegrityCheckFailed, 406),
        (TunnelError::InternalPeerRosterFull, 407),
    ];

    #[test]
    fn ppt_error_code_table_numbers_are_stable() {
        for (variant, expected_code) in ERROR_CODE_TABLE_FOR_TESTS.iter() {
            assert_eq!(variant.code(), *expected_code, "renumbered: {:?}", variant);
        }
    }

    #[test]
    fn ppt_is_retryable_only_socket_transients() {
        for (variant, _code) in ERROR_CODE_TABLE_FOR_TESTS.iter() {
            let expected_retryable = matches!(
                variant,
                TunnelError::SocketReadFailed
                    | TunnelError::SocketWriteFailed
                    | TunnelError::SocketSendIncomplete
            );
            assert_eq!(variant.is_retryable(), expected_retryable, "{:?}", variant);
        }
    }

    #[test]
    fn ppt_render_code_decimal_matches_code_for_every_variant() {
        for (variant, expected_code) in ERROR_CODE_TABLE_FOR_TESTS.iter() {
            let mut render_buffer = [0u8; ERROR_CODE_DECIMAL_MAX_DIGITS];
            let rendered = variant.render_code_decimal(&mut render_buffer).unwrap();
            assert_eq!(rendered, expected_code.to_string());
        }
    }

    #[test]
    fn ppt_display_includes_code_prefix() {
        let text = TunnelError::UdpChecksumMismatch.to_string();
        assert!(text.starts_with("PPT-13: "), "got {}", text);
    }

    #[test]
    fn ppt_error_size_is_two_bytes() {
        assert_eq!(std::mem::size_of::<TunnelError>(), 2);
    }

    // ----- Part 2: validated custom types (public constructors only) ---------

    /// TEST FIXTURE ONLY. Builds a complete IdentityRecord from text parts and
    /// a deterministic, non-zero salt pattern. Compiled only in test mode;
    /// never a default key. Reused by later parts' tests.
    fn build_fixture_identity_record_for_tests(
        identity_name_text: &str,
        ipv4_text: &str,
        port_text: &str,
        salt_pattern_seed: u32,
        validation_value: u32,
    ) -> IdentityRecord {
        let mut fixture_salt_values = [0u32; SALT_COUNT];
        for (salt_index, salt_slot) in fixture_salt_values.iter_mut().enumerate() {
            *salt_slot = salt_pattern_seed ^ 0x9E37_79B9u32.wrapping_mul(salt_index as u32 + 1);
        }
        let identity_name = IdentityName::parse_identity_name(identity_name_text).unwrap();
        let endpoint = Endpoint::from_validated_endpoint_parts(
            Ipv4Address::parse_ipv4_dotted_quad(ipv4_text).unwrap(),
            Port::parse_port_decimal_text(port_text).unwrap(),
        )
        .unwrap();
        let key_set = KeySet::from_validated_key_parts(
            SaltSet::from_parsed_salt_values(fixture_salt_values).unwrap(),
            ValidationByte::from_config_value_u32(validation_value).unwrap(),
        )
        .unwrap();
        IdentityRecord::from_validated_record_parts(identity_name, endpoint, key_set).unwrap()
    }

    #[test]
    fn ppt_parse_port_decimal_text_accepts_valid_ports() {
        assert_eq!(
            Port::parse_port_decimal_text("1")
                .unwrap()
                .get_port_number()
                .unwrap(),
            1
        );
        assert_eq!(
            Port::parse_port_decimal_text("40001")
                .unwrap()
                .get_port_number()
                .unwrap(),
            40001
        );
        assert_eq!(
            Port::parse_port_decimal_text("65535")
                .unwrap()
                .get_port_number()
                .unwrap(),
            65535
        );
    }

    #[test]
    fn ppt_parse_port_decimal_text_rejects_invalid_with_code_100() {
        for bad_port_text in [
            "", "0", "65536", "99999999", "08080", "80a", " 80", "+80", "-1",
        ] {
            let error = Port::parse_port_decimal_text(bad_port_text).unwrap_err();
            assert_eq!(
                error,
                TunnelError::ConfigInvalidPort,
                "input {:?}",
                bad_port_text
            );
            assert_eq!(error.code(), 100);
        }
    }

    #[test]
    fn ppt_parse_ipv4_dotted_quad_accepts_valid_addresses() {
        let parsed = Ipv4Address::parse_ipv4_dotted_quad("192.168.1.10").unwrap();
        assert_eq!(
            parsed.get_ipv4_addr().unwrap(),
            std::net::Ipv4Addr::new(192, 168, 1, 10)
        );
        let unspecified = Ipv4Address::parse_ipv4_dotted_quad("0.0.0.0").unwrap();
        assert_eq!(
            unspecified.get_ipv4_addr().unwrap(),
            std::net::Ipv4Addr::UNSPECIFIED
        );
        let max = Ipv4Address::parse_ipv4_dotted_quad("255.255.255.255").unwrap();
        assert_eq!(max.get_ipv4_addr().unwrap(), std::net::Ipv4Addr::BROADCAST);
    }

    #[test]
    fn ppt_parse_ipv4_dotted_quad_rejects_invalid_char_with_code_101() {
        for bad in ["1.2.3.a", " 1.2.3.4", "1.2.3.4 ", "1,2,3,4", "1.2.-3.4"] {
            let error = Ipv4Address::parse_ipv4_dotted_quad(bad).unwrap_err();
            assert_eq!(error, TunnelError::ConfigInvalidIp, "input {:?}", bad);
            assert_eq!(error.code(), 101);
        }
    }

    #[test]
    fn ppt_parse_ipv4_dotted_quad_rejects_empty_octet_with_code_112() {
        for bad in ["", "1..2.3", ".1.2.3", "1.2.3.", "...."] {
            let error = Ipv4Address::parse_ipv4_dotted_quad(bad).unwrap_err();
            assert_eq!(error, TunnelError::ConfigIpv4OctetEmpty, "input {:?}", bad);
            assert_eq!(error.code(), 112);
        }
    }

    #[test]
    fn ppt_parse_ipv4_dotted_quad_rejects_leading_zero_with_code_113() {
        for bad in ["010.1.1.1", "00.1.1.1", "1.2.3.04"] {
            let error = Ipv4Address::parse_ipv4_dotted_quad(bad).unwrap_err();
            assert_eq!(
                error,
                TunnelError::ConfigIpv4OctetLeadingZero,
                "input {:?}",
                bad
            );
            assert_eq!(error.code(), 113);
        }
    }

    #[test]
    fn ppt_parse_ipv4_dotted_quad_rejects_out_of_range_with_code_114() {
        for bad in ["256.1.1.1", "1.2.3.999", "1234.1.1.1"] {
            let error = Ipv4Address::parse_ipv4_dotted_quad(bad).unwrap_err();
            assert_eq!(
                error,
                TunnelError::ConfigIpv4OctetOutOfRange,
                "input {:?}",
                bad
            );
            assert_eq!(error.code(), 114);
        }
    }

    #[test]
    fn ppt_parse_ipv4_dotted_quad_rejects_wrong_count_with_code_115() {
        for bad in ["1.2.3", "1", "1.2.3.4.5"] {
            let error = Ipv4Address::parse_ipv4_dotted_quad(bad).unwrap_err();
            assert_eq!(
                error,
                TunnelError::ConfigIpv4WrongOctetCount,
                "input {:?}",
                bad
            );
            assert_eq!(error.code(), 115);
        }
    }

    #[test]
    fn ppt_parse_identity_name_accepts_and_round_trips() {
        for good in ["alice", "Bob_North", "team-4", "a", "A1_b2-C3"] {
            let parsed = IdentityName::parse_identity_name(good).unwrap();
            assert_eq!(parsed.get_identity_name_str().unwrap(), good);
        }
        let max_len_name = "n".repeat(IDENTITY_NAME_MAX_BYTES);
        let parsed = IdentityName::parse_identity_name(&max_len_name).unwrap();
        assert_eq!(parsed.get_identity_name_str().unwrap(), max_len_name);
    }

    #[test]
    fn ppt_parse_identity_name_rejects_empty_with_code_116() {
        let error = IdentityName::parse_identity_name("").unwrap_err();
        assert_eq!(error, TunnelError::ConfigIdentityNameEmpty);
        assert_eq!(error.code(), 116);
    }

    #[test]
    fn ppt_parse_identity_name_rejects_invalid_char_with_code_117() {
        for bad in ["al ice", "a=b", "a#b", "\"alice\"", "alice\n", "café"] {
            let error = IdentityName::parse_identity_name(bad).unwrap_err();
            assert_eq!(
                error,
                TunnelError::ConfigIdentityNameInvalidChar,
                "input {:?}",
                bad
            );
            assert_eq!(error.code(), 117);
        }
    }

    #[test]
    fn ppt_parse_identity_name_rejects_too_long_with_code_118() {
        let too_long = "n".repeat(IDENTITY_NAME_MAX_BYTES + 1);
        let error = IdentityName::parse_identity_name(&too_long).unwrap_err();
        assert_eq!(error, TunnelError::ConfigIdentityNameTooLong);
        assert_eq!(error.code(), 118);
    }

    #[test]
    fn ppt_from_config_value_u32_validation_byte_bounds_with_code_106() {
        assert_eq!(
            ValidationByte::from_config_value_u32(0)
                .unwrap()
                .get_validation_byte_value()
                .unwrap(),
            0
        );
        assert_eq!(
            ValidationByte::from_config_value_u32(255)
                .unwrap()
                .get_validation_byte_value()
                .unwrap(),
            255
        );
        // Previously truncated silently by `as u8` (LHF-10): 0x144 would have become 0x44.
        for bad in [256u32, 0x144, u32::MAX] {
            let error = ValidationByte::from_config_value_u32(bad).err().unwrap();
            assert_eq!(error, TunnelError::ConfigValidationByteOutOfRange);
            assert_eq!(error.code(), 106);
        }
    }

    #[test]
    fn ppt_from_parsed_salt_values_rejects_all_zero_with_code_122() {
        let error = SaltSet::from_parsed_salt_values([0u32; SALT_COUNT])
            .err()
            .unwrap();
        assert_eq!(error, TunnelError::ConfigSaltSetAllZero);
        assert_eq!(error.code(), 122);
        // A single non-zero salt is accepted (this is not a strength test).
        let mut one_nonzero = [0u32; SALT_COUNT];
        one_nonzero[SALT_COUNT - 1] = 1;
        assert!(SaltSet::from_parsed_salt_values(one_nonzero).is_ok());
    }

    #[test]
    fn ppt_get_salt_groups_per_table_splits_halves_in_order() {
        let mut ordered_salts = [0u32; SALT_COUNT];
        for (salt_index, salt_slot) in ordered_salts.iter_mut().enumerate() {
            *salt_slot = salt_index as u32 + 100;
        }
        let salt_set = SaltSet::from_parsed_salt_values(ordered_salts).unwrap();
        let (table_1_group, table_2_group) = salt_set.get_salt_groups_per_table().unwrap();
        assert_eq!(table_1_group[..], ordered_salts[..SALT_GROUP_SIZE]);
        assert_eq!(table_2_group[..], ordered_salts[SALT_GROUP_SIZE..]);
    }

    #[test]
    fn ppt_get_socket_address_v4_round_trips() {
        let record =
            build_fixture_identity_record_for_tests("alice", "127.0.0.1", "40001", 7, 0x44);
        let socket_address = record
            .borrow_record_endpoint()
            .get_socket_address_v4()
            .unwrap();
        assert_eq!(socket_address, "127.0.0.1:40001".parse().unwrap());
        assert_eq!(
            record
                .borrow_record_key_set()
                .get_expected_validation_byte()
                .unwrap(),
            0x44
        );
        assert_eq!(
            record
                .borrow_record_identity_name()
                .get_identity_name_str()
                .unwrap(),
            "alice"
        );
    }

    #[test]
    fn ppt_require_at_least_one_peer_configured_rejects_empty_with_code_105() {
        let roster = PeerRoster::create_empty_peer_roster();
        let error = roster.require_at_least_one_peer_configured().unwrap_err();
        assert_eq!(error, TunnelError::ConfigNoPeersConfigured);
        assert_eq!(error.code(), 105);
    }

    #[test]
    fn ppt_iterate_peer_records_preserves_order() {
        let mut roster = PeerRoster::create_empty_peer_roster();
        roster
            .append_peer_record(build_fixture_identity_record_for_tests(
                "alice",
                "127.0.0.1",
                "40001",
                1,
                1,
            ))
            .unwrap();
        roster
            .append_peer_record(build_fixture_identity_record_for_tests(
                "carol",
                "127.0.0.1",
                "40003",
                3,
                3,
            ))
            .unwrap();
        roster.require_at_least_one_peer_configured().unwrap();
        assert_eq!(roster.get_peer_count().unwrap(), 2);
        let mut seen_names: Vec<String> = Vec::new();
        for peer_record in roster.iterate_peer_records().unwrap() {
            seen_names.push(
                peer_record
                    .borrow_record_identity_name()
                    .get_identity_name_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_eq!(seen_names, vec!["alice".to_string(), "carol".to_string()]);
    }
}
