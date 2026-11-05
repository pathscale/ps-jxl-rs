#![no_main]

use jxl::api::{Event, JxlAuxBoxType, JxlDecoder, JxlDecoderOptions};
use jxl_fuzz::FUZZ_SAMPLE_LIMIT;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let kinds = [JxlAuxBoxType::EXIF, JxlAuxBoxType::XMP];
    let mut options = JxlDecoderOptions::default();
    options.sample_limit = Some(FUZZ_SAMPLE_LIMIT);
    options.scan_frames_only = true;
    options.request_aux_boxes = kinds.to_vec();
    let mut decoder = JxlDecoder::new(options);
    let mut input = data;
    decoder.close_input();
    for _ in 0..1024 {
        match decoder.process(&mut input, None, None) {
            Ok(Event::Complete) => break,
            Ok(Event::NeedMoreInput { .. }) | Err(_) => return,
            _ => {}
        }
    }
    for kind in kinds {
        for aux in decoder.aux_boxes(kind) {
            let _ = aux.data(&[]);
        }
    }
    if let Some(aux) = decoder.trailing_box() {
        let _ = aux.data(input);
    }
});
