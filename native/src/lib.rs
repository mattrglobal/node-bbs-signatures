use neon::prelude::*;
use neon::result::Throw;
use neon::register_module;
use zmix::signatures::SignatureMessage;
use zmix::signatures::bbs::prelude::*;
use zmix::signatures::bbs::keys::prelude::*;
// use zmix::amcl_wrapper::{group_elem_g1::G1, field_elem::FieldElement, group_elem::GroupElement};
// use zmix::hash2curve::{bls381g1::Bls12381G1Sswu, HashToCurveXmd};

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g2` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_key(mut cx: FunctionContext) -> JsResult<JsObject> {
    // let seed =
    //     match cx.argument_opt(0) {
    //         Some(arg) => {
    //             let arg: Handle<JsArrayBuffer> = arg.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
    //             let seed_data = cx.borrow(&arg, |data| { data.as_slice::<u8>() });
    //             Some(seed_data)
    //         },
    //         None => None
    //     };

    let (pk, sk) = DeterministicPublicKey::new(None);

    let pk_bytes = pk.to_bytes();
    let mut pk_array = JsArrayBuffer::new(&mut cx, 192 as u32)?;
    cx.borrow_mut(&mut pk_array, |slice| {
        let bytes = slice.as_mut_slice::<u8>();
        bytes.copy_from_slice(pk_bytes.as_slice());
    });

    let sk_bytes = sk.to_bytes();
    let mut sk_array = JsArrayBuffer::new(&mut cx, 48 as u32)?;
    cx.borrow_mut(&mut sk_array, |slice| {
        let bytes = slice.as_mut_slice::<u8>();
        bytes.copy_from_slice(sk_bytes.as_slice());
    });

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "publicKey", pk_array)?;
    result.set(&mut cx, "secretKey", sk_array)?;

    Ok(result)
}

/// Computes `u` = `generator`^`value`
/// `generator` is expected to be in G1 and `value` is handled in Fp
///
/// `generator`: `ArrayBuffer` length must be `COMMITMENT_SIZE`
/// `value`: `ArrayBuffer` length must be `MESSAGE_SIZE`
/// `return`: `ArrayBuffer`
// fn bls_commitment(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
//     let generator: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(0)?;
//     let value: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(1)?;

//     let base = cx.borrow(&generator, |data| { data.as_slice::<u8>() });

//     if base.len() != COMMITMENT_SIZE {
//         return Err(Throw);
//     }

//     let exponent = cx.borrow(&value, |data| { data.as_slice::<u8>() });

//     if exponent.len() != MESSAGE_SIZE {
//         return Err(Throw);
//     }

//     let g = G1::from_bytes(base).map_err(|_| Throw)?;
//     let e = amcl_wrapper::field_elem::FieldElement::from_bytes(exponent).map_err(|_| Throw)?;
//     let res = g.scalar_mul_const_time(&e);

//     let mut commitment = JsArrayBuffer::new(&mut cx, SECRET_KEY_SIZE as u32)?;
//     cx.borrow_mut(&mut commitment, |slice| {
//         let bytes = slice.as_mut_slice::<u8>();
//         bytes.copy_from_slice(res.to_bytes().as_slice());
//     });
//     Ok(commitment)
// }

/// Create a generator in G1
/// `seed`: `ArrayBuffer` [opt]
///
/// `return`: `ArrayBuffer`
// fn bls_create_generator_g1(mut cx: FunctionContent) -> JsResult<JsArrayBuffer> {
//     let seed =
//         match cx.argument_opt(0) {
//             Some(arg) => {
//                 let arg: Handle<JsArrayBuffer> = arg.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
//                 let seed_data = cx.borrow(&arg, |data| { data.as_slice::<u8>() });
//                 Some(KeyGenOption::UseSeed(seed_data.to_vec()))
//             },
//             None => G1::generator()
//         };
//
//
// }

// declare_types! {
//   pub class JsBlsKeyPair for BlsKeyPair {
//     init(mut cx) {
//
//       let seed = match cx.argument_opt(0) {
//         Some(arg) => {
//             let seed_type: Handle<JsString> = arg.downcast::<Js>
//             let bytes: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(1)?;
//             match arg {
//                 "seed" => {
//                 },
//                 "key" => {
//
//                 },
//                 _ => None
//             }
//         },
//         None => None
//       };

      // let seed =
      //   match cx.argument_opt(1) {
      //       Some(arg) => {
      //           let arg: Handle<JsArrayBuffer> = arg.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
      //           let seed_data = cx.borrow(&arg, |data| { data.as_slice::<u8>() });
      //           Some(KeyGenOption::UseSeed(seed_data.to_vec()))
      //       },
      //       None => None
      //   };

      // let (pk, sk) = DeterministicPublicKey::new(seed);
      //
      // Ok(BlsKeyPair { pk, sk: Some(sk) })
    // }
    //
    // method fromPrivateKey(mut cx) {
    //     let arg: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(0)?;
    //
    //     let sk = cx.borrow(&arg, |data| { data.as_slice::<u8>() } );
    //
    //     if sk.len() != SECRET_KEY_SIZE {
    //         return Err(Throw);
    //     }
    //
    //     let (pk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(RawPrivateKey(sk.to_vec()))));
    //
    //     Ok(BlsKeyPair { pk, sk: Some(sk) })
    // }
    //
    // method publicKey(mut cx) {
    //     let this = cx.this();
    //
    //     let pk = {
    //         let guard = cx.lock();
    //         let keypair = this.borrow(&guard);
    //         keypair.pk.to_bytes()
    //     };
    //     let mut js_array = JsArrayBuffer::new(&mut cx, pk.len() as u32)?;
    //     cx.borrow_mut(&mut js_array, |slice| {
    //         let bytes = slice.as_mut_slice::<u8>();
    //         for i in 0..pk.len() {
    //             bytes[i] = pk[i];
    //         }
    //     });
    //     Ok(js_array.upcast())
    // }

    // method secretKey(mut cx) {
    //     let this = cx.this();
    //
    //     let sk = {
    //         let guard = cx.lock();
    //         let keypair = this.borrow(&guard);
    //         keypair.sk
    //     };
    //     match sk {
    //         Some(k) => {
    //             let data = k.to_bytes();
    //             let mut js_array = JsArrayBuffer::new(&mut cx, data.len() as u32)?;
    //             cx.borrow_mut(&mut js_array, |slice| {
    //                 let bytes = slice.as_mut_slice::<u8>();
    //                 for i in 0..data.len() {
    //                     bytes[i] = data[i];
    //                 }
    //             });
    //             Ok(js_array.upcast())
    //         },
    //         None => {
    //             Ok(cx.empty_array().upcast())
    //         }
    //     }
    // }

    // method bbs_sign(mut cx) {
        // let args_length = cx.len();
        //
        // let messages = Vec::with_capacity(args_length as usize);
        // for i in 0..args_length {
        //     let arg: Handle<JsArrayBuffer> = cx.argument::<JsArrayBuffer>(i)?;
        //     let data = cx.borrow(&arg, |data| { data.as_slice::<u8>() });
        //
        //     let m = SignatureMessage::from_bytes(data)?;
        //     messages.push(m);
        // }
        //
        // let this = cx.this();
        // let sk = {
        //     let guard = cx.lock();
        //     let keypair = this.borrow(&guard);
        //     keypair.sk.to_bytes()
        // };
        // Ok(())
    // }

    // method panic(_) {
    //   panic!("BbsKeyPair.prototype.panic")
    // }
  // }
// }

register_module!(mut m, {
    m.export_function("bls_generate_key", bls_generate_key)?;
    //m.export_function("bls_commitment", bls_commitment)?;
    // m.export_class::<JsBlsKeyPair>("BbsKeyPair")?;
    Ok(())
});