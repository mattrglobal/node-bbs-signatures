macro_rules! slice_to_js_array_buffer {
    ($slice:expr, $cx:expr) => {
        {
            let mut result = JsArrayBuffer::new(&mut $cx, $slice.len() as u32)?;
            $cx.borrow_mut(&mut result, |d| {
                let bytes = d.as_mut_slice::<u8>();
                bytes.copy_from_slice($slice);
            });
            result
        }
    };
}

macro_rules! arg_to_slice {
    ($cx:expr, $i:expr) => {
        {
            let arg: Handle<JsArrayBuffer> = $cx.argument::<JsArrayBuffer>($i)?;
            $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
        }
    };
}

macro_rules! obj_field_to_slice {
    ($cx:expr, $obj:expr, $field:expr) => {
        {
            let arg: Handle<JsArrayBuffer> = $obj
                .get($cx, $field)?
                .downcast::<JsArrayBuffer>()
                .or_throw($cx)?;
            $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
        }
    };
}

macro_rules! obj_field_to_opt_bytes {
    ($cx:expr, $obj:expr, $field:expr) => {
        {
            let t: Option<Vec<u8>> = match $obj
                .get($cx, $field)?
                .downcast::<JsArrayBuffer>()
                .or_throw($cx)
            {
                Err(_) => None,
                Ok(arg) => Some($cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()),
            };
            t
        }
    };
}

macro_rules! obj_field_to_vec {
    ($cx:expr, $obj:expr, $field: expr) => {
        {
            let v: Vec<Handle<JsValue>> = $obj.get($cx, $field)?
                                        .downcast::<JsArray>()
                                        .or_throw($cx)?
                                        .to_vec($cx)?;
            v
        }
    };
}

macro_rules! cast_to_slice {
    ($cx:expr, $obj:expr) => {
        {
            let arg = $obj.downcast::<JsArrayBuffer>().or_throw($cx)?;
            $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
        }
    };
}