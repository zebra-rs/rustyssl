use super::{Driver, track_records};

#[test]
fn records_split_anywhere() {
    // Two TLS records (3 and 0 octets of body), fed one octet at a time.
    let input = [22u8, 3, 3, 0, 3, 1, 2, 3, 21, 3, 3, 0, 0];
    let mut d = Driver::default();
    for (i, b) in input.iter().enumerate() {
        track_records(&mut d, false, core::slice::from_ref(b));
        match i {
            4 => assert_eq!(d.rec_left, 3),
            7 => {
                assert_eq!(d.rec_left, 0);
                assert!(d.rec_header.is_empty());
                assert!(d.first_record_done);
            }
            _ => {}
        }
    }
    assert_eq!(d.rec_left, 0);
    assert!(d.rec_header.is_empty());
}

#[test]
fn records_in_one_read() {
    let mut d = Driver::default();
    track_records(&mut d, false, &[23, 3, 3, 0, 2, 9, 9, 23, 3, 3, 1]);
    // The second record's header is still incomplete.
    assert_eq!(d.rec_left, 0);
    assert_eq!(d.rec_header, [23, 3, 3, 1]);
    track_records(&mut d, false, &[0]);
    assert_eq!(d.rec_left, 256);
}

#[test]
fn sslv2_hello_on_a_server_only() {
    let mut d = Driver::default();
    track_records(&mut d, true, &[0x80, 0x2e]);
    assert_eq!(d.rec_left, 0x2e);

    // A client reads a five-octet header whatever the first octet.
    let mut d = Driver::default();
    track_records(&mut d, false, &[0x80, 0x2e, 3, 0, 2]);
    assert_eq!(d.rec_left, 2);

    // After the first record, a server reads TLS headers too.
    let mut d = Driver::default();
    track_records(&mut d, true, &[22, 3, 1, 0, 1, 0]);
    track_records(&mut d, true, &[0x80, 3, 3, 0, 1]);
    assert_eq!(d.rec_left, 1);
}
