/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

macro_rules! slice_to_js_array_buffer {
    ($slice:expr, $cx:expr) => {{
        let mut result = JsArrayBuffer::new(&mut $cx, $slice.len() as u32)?;
        $cx.borrow_mut(&mut result, |d| {
            let bytes = d.as_mut_slice::<u8>();
            bytes.copy_from_slice($slice);
        });
        result
    }};
}

macro_rules! arg_to_slice {
    ($cx:expr, $i:expr) => {{
        let arg: Handle<JsArrayBuffer> = $cx.argument::<JsArrayBuffer>($i)?;
        $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
    }};
}

macro_rules! arg_to_fixed_array {
    ($cx:expr, $i:expr, $start:expr, $end:expr) => {{
        let a = arg_to_slice!($cx, $i);
        if a.len() != $end {
            panic!("Invalid length");
        }
        *array_ref![a, $start, $end]
    }};
}

macro_rules! obj_field_to_slice {
    ($cx:expr, $obj:expr, $field:expr) => {{
        let a = $obj.get::<JsArrayBuffer, _, _>($cx, $field)?.deref();
        a.borrow(&$cx.lock()).deref().as_slice()
    }};
}

macro_rules! obj_field_to_fixed_array {
    ($cx:expr, $obj:expr, $field:expr, $start:expr, $end:expr) => {{
        let a: &JsArrayBuffer = $obj.get::<JsArrayBuffer, _, _>($cx, $field)?.deref();
        let b =  a.borrow(&$cx.lock()).deref().as_slice();
        if b.len() != $end {
            panic!("Invalid length");
        }
        *array_ref![b, $start, $end]
    }};
}

macro_rules! obj_field_to_opt_slice {
    ($cx:expr, $obj:expr, $field:expr) => {{
        match $obj.get::<JsArrayBuffer, _, _>($cx, $field) {
            Err(_) => None,
            Ok(arg) => Some(arg.borrow(&$cx.lock()).deref().as_slice().to_vec())
        }
    }};
}

macro_rules! obj_field_to_vec {
    ($cx:expr, $obj:expr, $field: expr) => {{
        let v = $obj
            .get::<JsValue, _, _>($cx, $field)?
            .downcast::<JsArray>()
            .or_throw($cx)?
            .to_vec($cx)?;
        v
    }};
}

macro_rules! cast_to_number {
    ($cx:expr, $obj:expr) => {
        $obj.downcast::<JsNumber>()
            .unwrap_or($cx.number(-1))
            .value()
    };
}

macro_rules! handle_err {
    ($e:expr) => {
        $e.map_err(|e| format!("{:?}", e)).unwrap()
    };
}

macro_rules! obj_field_to_field_elem {
    ($cx:expr, $d:expr) => {{
        //let m = $d.as_slice(&$cx);
        let m = $d.downcast::<JsObject>()
            .or_throw($cx)?
            .get::<JsArrayBuffer, _, _>($cx, $d)?
            .borrow(&$cx.lock())
            .deref()
            .as_slice();//cast_to_slice!($cx, $d);
        SignatureMessage::hash(m)
    }};
}

macro_rules! get_message_count {
    ($cx:expr, $obj:expr, $field:expr) => {{
        let message_count: f64 = $obj
            .get::<JsNumber, _, _>($cx, $field)?
            //.downcast::<JsNumber>()
            //.unwrap_or($cx.number(-1))
            .value();

        if message_count < 0f64 {
            panic!("Message count cannot be negative: {}", message_count);
        }
        message_count
    }};
}
