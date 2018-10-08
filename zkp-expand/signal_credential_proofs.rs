#![feature(prelude_import)]
#![no_std]
// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![no_std]
#[prelude_import]
use ::core::prelude::v1::*;
#[macro_use]
extern crate core as core;
#[macro_use]
extern crate compiler_builtins as compiler_builtins;

#[cfg(any(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate zkp;

pub mod proofs {
    //! Zero-knowledge proofs.
    //!
    //! # Note
    //!
    //! The notation and variable names used throughout this module are that of
    //! [LdV'17](https://patternsinthevoid.net/hyphae/hyphae.pdf), not those of
    //! [CMZ'13](https://eprint.iacr.org/2013/516.pdf) because the latter was
    //! missing signification details of the construction.
    pub mod _blind_attributes {
        use ::curve25519_dalek::scalar::Scalar;
        use ::curve25519_dalek::ristretto::RistrettoPoint;
        use ::curve25519_dalek::traits::{MultiscalarMul,
                                         VartimeMultiscalarMul};
        use ::merlin::Transcript;
        use ::rand::thread_rng;
        #[cfg(not(feature = "std"))]
        use core::iter;
        #[rustc_copy_clone_marker]
        pub struct Secrets<'a> {
            pub d: &'a Scalar,
            pub e0: &'a Scalar,
            pub m0: &'a Scalar,
            pub nonce: &'a Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::marker::Copy for Secrets<'a> { }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::clone::Clone for Secrets<'a> {
            #[inline]
            fn clone(&self) -> Secrets<'a> {
                {
                    let _: ::core::clone::AssertParamIsClone<&'a Scalar>;
                    let _: ::core::clone::AssertParamIsClone<&'a Scalar>;
                    let _: ::core::clone::AssertParamIsClone<&'a Scalar>;
                    let _: ::core::clone::AssertParamIsClone<&'a Scalar>;
                    *self
                }
            }
        }
        #[rustc_copy_clone_marker]
        pub struct Publics<'a> {
            pub B: &'a RistrettoPoint,
            pub A: &'a RistrettoPoint,
            pub D: &'a RistrettoPoint,
            pub roster_entry: &'a RistrettoPoint,
            pub encrypted_attribute_0_0: &'a RistrettoPoint,
            pub encrypted_attribute_0_1: &'a RistrettoPoint,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::marker::Copy for Publics<'a> { }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::clone::Clone for Publics<'a> {
            #[inline]
            fn clone(&self) -> Publics<'a> {
                {
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    *self
                }
            }
        }
        struct Commitments {
            D: RistrettoPoint,
            encrypted_attribute_0_0: RistrettoPoint,
            encrypted_attribute_0_1: RistrettoPoint,
            roster_entry: RistrettoPoint,
        }
        struct Randomnesses {
            d: Scalar,
            e0: Scalar,
            m0: Scalar,
            nonce: Scalar,
        }
        #[structural_match]
        struct Responses {
            d: Scalar,
            e0: Scalar,
            m0: Scalar,
            nonce: Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for Responses {
            #[inline]
            fn clone(&self) -> Responses {
                match *self {
                    Responses {
                    d: ref __self_0_0,
                    e0: ref __self_0_1,
                    m0: ref __self_0_2,
                    nonce: ref __self_0_3 } =>
                    Responses{d: ::core::clone::Clone::clone(&(*__self_0_0)),
                              e0: ::core::clone::Clone::clone(&(*__self_0_1)),
                              m0: ::core::clone::Clone::clone(&(*__self_0_2)),
                              nonce:
                                  ::core::clone::Clone::clone(&(*__self_0_3)),},
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::fmt::Debug for Responses {
            fn fmt(&self, f: &mut ::core::fmt::Formatter)
             -> ::core::fmt::Result {
                match *self {
                    Responses {
                    d: ref __self_0_0,
                    e0: ref __self_0_1,
                    m0: ref __self_0_2,
                    nonce: ref __self_0_3 } => {
                        let mut debug_trait_builder =
                            f.debug_struct("Responses");
                        let _ =
                            debug_trait_builder.field("d", &&(*__self_0_0));
                        let _ =
                            debug_trait_builder.field("e0", &&(*__self_0_1));
                        let _ =
                            debug_trait_builder.field("m0", &&(*__self_0_2));
                        let _ =
                            debug_trait_builder.field("nonce",
                                                      &&(*__self_0_3));
                        debug_trait_builder.finish()
                    }
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::Eq for Responses {
            #[inline]
            #[doc(hidden)]
            fn assert_receiver_is_total_eq(&self) -> () {
                {
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::PartialEq for Responses {
            #[inline]
            fn eq(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    d: ref __self_1_0,
                    e0: ref __self_1_1,
                    m0: ref __self_1_2,
                    nonce: ref __self_1_3 } =>
                    match *self {
                        Responses {
                        d: ref __self_0_0,
                        e0: ref __self_0_1,
                        m0: ref __self_0_2,
                        nonce: ref __self_0_3 } =>
                        (*__self_0_0) == (*__self_1_0) &&
                            (*__self_0_1) == (*__self_1_1) &&
                            (*__self_0_2) == (*__self_1_2) &&
                            (*__self_0_3) == (*__self_1_3),
                    },
                }
            }
            #[inline]
            fn ne(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    d: ref __self_1_0,
                    e0: ref __self_1_1,
                    m0: ref __self_1_2,
                    nonce: ref __self_1_3 } =>
                    match *self {
                        Responses {
                        d: ref __self_0_0,
                        e0: ref __self_0_1,
                        m0: ref __self_0_2,
                        nonce: ref __self_0_3 } =>
                        (*__self_0_0) != (*__self_1_0) ||
                            (*__self_0_1) != (*__self_1_1) ||
                            (*__self_0_2) != (*__self_1_2) ||
                            (*__self_0_3) != (*__self_1_3),
                    },
                }
            }
        }
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_SERIALIZE_FOR_Responses: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl _serde::Serialize for Responses {
                    fn serialize<__S>(&self, __serializer: __S)
                     -> _serde::export::Result<__S::Ok, __S::Error> where
                     __S: _serde::Serializer {
                        let mut __serde_state =
                            match _serde::Serializer::serialize_struct(__serializer,
                                                                       "Responses",
                                                                       0 + 1 +
                                                                           1 +
                                                                           1 +
                                                                           1)
                                {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "d",
                                                                            &self.d)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "e0",
                                                                            &self.e0)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "m0",
                                                                            &self.m0)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "nonce",
                                                                            &self.nonce)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_DESERIALIZE_FOR_Responses: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl <'de> _serde::Deserialize<'de> for Responses {
                    fn deserialize<__D>(__deserializer: __D)
                     -> _serde::export::Result<Self, __D::Error> where
                     __D: _serde::Deserializer<'de> {
                        #[allow(non_camel_case_types)]
                        enum __Field {
                            __field0,
                            __field1,
                            __field2,
                            __field3,
                            __ignore,
                        }
                        struct __FieldVisitor;
                        impl <'de> _serde::de::Visitor<'de> for __FieldVisitor
                         {
                            type
                            Value
                            =
                            __Field;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "field identifier")
                            }
                            fn visit_u64<__E>(self, __value: u64)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    0u64 =>
                                    _serde::export::Ok(__Field::__field0),
                                    1u64 =>
                                    _serde::export::Ok(__Field::__field1),
                                    2u64 =>
                                    _serde::export::Ok(__Field::__field2),
                                    3u64 =>
                                    _serde::export::Ok(__Field::__field3),
                                    _ =>
                                    _serde::export::Err(_serde::de::Error::invalid_value(_serde::de::Unexpected::Unsigned(__value),
                                                                                         &"field index 0 <= i < 4")),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    "d" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "e0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    "m0" =>
                                    _serde::export::Ok(__Field::__field2),
                                    "nonce" =>
                                    _serde::export::Ok(__Field::__field3),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8])
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    b"d" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"e0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    b"m0" =>
                                    _serde::export::Ok(__Field::__field2),
                                    b"nonce" =>
                                    _serde::export::Ok(__Field::__field3),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                        }
                        impl <'de> _serde::Deserialize<'de> for __Field {
                            #[inline]
                            fn deserialize<__D>(__deserializer: __D)
                             -> _serde::export::Result<Self, __D::Error> where
                             __D: _serde::Deserializer<'de> {
                                _serde::Deserializer::deserialize_identifier(__deserializer,
                                                                             __FieldVisitor)
                            }
                        }
                        struct __Visitor<'de> {
                            marker: _serde::export::PhantomData<Responses>,
                            lifetime: _serde::export::PhantomData<&'de ()>,
                        }
                        impl <'de> _serde::de::Visitor<'de> for __Visitor<'de>
                         {
                            type
                            Value
                            =
                            Responses;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "struct Responses")
                            }
                            #[inline]
                            fn visit_seq<__A>(self, mut __seq: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::SeqAccess<'de> {
                                let __field0 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(0usize,
                                                                                                         &"struct Responses with 4 elements"));
                                        }
                                    };
                                let __field1 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(1usize,
                                                                                                         &"struct Responses with 4 elements"));
                                        }
                                    };
                                let __field2 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(2usize,
                                                                                                         &"struct Responses with 4 elements"));
                                        }
                                    };
                                let __field3 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(3usize,
                                                                                                         &"struct Responses with 4 elements"));
                                        }
                                    };
                                _serde::export::Ok(Responses{d: __field0,
                                                             e0: __field1,
                                                             m0: __field2,
                                                             nonce:
                                                                 __field3,})
                            }
                            #[inline]
                            fn visit_map<__A>(self, mut __map: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::MapAccess<'de> {
                                let mut __field0:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                let mut __field1:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                let mut __field2:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                let mut __field3:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                while let _serde::export::Some(__key) =
                                          match _serde::de::MapAccess::next_key::<__Field>(&mut __map)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                    match __key {
                                        __Field::__field0 => {
                                            if _serde::export::Option::is_some(&__field0)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("d"));
                                            }
                                            __field0 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        __Field::__field1 => {
                                            if _serde::export::Option::is_some(&__field1)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("e0"));
                                            }
                                            __field1 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        __Field::__field2 => {
                                            if _serde::export::Option::is_some(&__field2)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("m0"));
                                            }
                                            __field2 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        __Field::__field3 => {
                                            if _serde::export::Option::is_some(&__field3)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("nonce"));
                                            }
                                            __field3 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        _ => {
                                            let _ =
                                                match _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(&mut __map)
                                                    {
                                                    _serde::export::Ok(__val)
                                                    => __val,
                                                    _serde::export::Err(__err)
                                                    => {
                                                        return _serde::export::Err(__err);
                                                    }
                                                };
                                        }
                                    }
                                }
                                let __field0 =
                                    match __field0 {
                                        _serde::export::Some(__field0) =>
                                        __field0,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("d")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field1 =
                                    match __field1 {
                                        _serde::export::Some(__field1) =>
                                        __field1,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("e0")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field2 =
                                    match __field2 {
                                        _serde::export::Some(__field2) =>
                                        __field2,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("m0")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field3 =
                                    match __field3 {
                                        _serde::export::Some(__field3) =>
                                        __field3,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("nonce")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Responses{d: __field0,
                                                             e0: __field1,
                                                             m0: __field2,
                                                             nonce:
                                                                 __field3,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["d", "e0", "m0", "nonce"];
                        _serde::Deserializer::deserialize_struct(__deserializer,
                                                                 "Responses",
                                                                 FIELDS,
                                                                 __Visitor{marker:
                                                                               _serde::export::PhantomData::<Responses>,
                                                                           lifetime:
                                                                               _serde::export::PhantomData,})
                    }
                }
            };
        #[structural_match]
        pub struct Proof {
            challenge: Scalar,
            responses: Responses,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for Proof {
            #[inline]
            fn clone(&self) -> Proof {
                match *self {
                    Proof {
                    challenge: ref __self_0_0, responses: ref __self_0_1 } =>
                    Proof{challenge:
                              ::core::clone::Clone::clone(&(*__self_0_0)),
                          responses:
                              ::core::clone::Clone::clone(&(*__self_0_1)),},
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::fmt::Debug for Proof {
            fn fmt(&self, f: &mut ::core::fmt::Formatter)
             -> ::core::fmt::Result {
                match *self {
                    Proof {
                    challenge: ref __self_0_0, responses: ref __self_0_1 } =>
                    {
                        let mut debug_trait_builder = f.debug_struct("Proof");
                        let _ =
                            debug_trait_builder.field("challenge",
                                                      &&(*__self_0_0));
                        let _ =
                            debug_trait_builder.field("responses",
                                                      &&(*__self_0_1));
                        debug_trait_builder.finish()
                    }
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::Eq for Proof {
            #[inline]
            #[doc(hidden)]
            fn assert_receiver_is_total_eq(&self) -> () {
                {
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                    let _: ::core::cmp::AssertParamIsEq<Responses>;
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::PartialEq for Proof {
            #[inline]
            fn eq(&self, other: &Proof) -> bool {
                match *other {
                    Proof {
                    challenge: ref __self_1_0, responses: ref __self_1_1 } =>
                    match *self {
                        Proof {
                        challenge: ref __self_0_0, responses: ref __self_0_1 }
                        =>
                        (*__self_0_0) == (*__self_1_0) &&
                            (*__self_0_1) == (*__self_1_1),
                    },
                }
            }
            #[inline]
            fn ne(&self, other: &Proof) -> bool {
                match *other {
                    Proof {
                    challenge: ref __self_1_0, responses: ref __self_1_1 } =>
                    match *self {
                        Proof {
                        challenge: ref __self_0_0, responses: ref __self_0_1 }
                        =>
                        (*__self_0_0) != (*__self_1_0) ||
                            (*__self_0_1) != (*__self_1_1),
                    },
                }
            }
        }
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_SERIALIZE_FOR_Proof: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl _serde::Serialize for Proof {
                    fn serialize<__S>(&self, __serializer: __S)
                     -> _serde::export::Result<__S::Ok, __S::Error> where
                     __S: _serde::Serializer {
                        let mut __serde_state =
                            match _serde::Serializer::serialize_struct(__serializer,
                                                                       "Proof",
                                                                       0 + 1 +
                                                                           1)
                                {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "challenge",
                                                                            &self.challenge)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "responses",
                                                                            &self.responses)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_DESERIALIZE_FOR_Proof: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl <'de> _serde::Deserialize<'de> for Proof {
                    fn deserialize<__D>(__deserializer: __D)
                     -> _serde::export::Result<Self, __D::Error> where
                     __D: _serde::Deserializer<'de> {
                        #[allow(non_camel_case_types)]
                        enum __Field { __field0, __field1, __ignore, }
                        struct __FieldVisitor;
                        impl <'de> _serde::de::Visitor<'de> for __FieldVisitor
                         {
                            type
                            Value
                            =
                            __Field;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "field identifier")
                            }
                            fn visit_u64<__E>(self, __value: u64)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    0u64 =>
                                    _serde::export::Ok(__Field::__field0),
                                    1u64 =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ =>
                                    _serde::export::Err(_serde::de::Error::invalid_value(_serde::de::Unexpected::Unsigned(__value),
                                                                                         &"field index 0 <= i < 2")),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    "challenge" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "responses" =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8])
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    b"challenge" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"responses" =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                        }
                        impl <'de> _serde::Deserialize<'de> for __Field {
                            #[inline]
                            fn deserialize<__D>(__deserializer: __D)
                             -> _serde::export::Result<Self, __D::Error> where
                             __D: _serde::Deserializer<'de> {
                                _serde::Deserializer::deserialize_identifier(__deserializer,
                                                                             __FieldVisitor)
                            }
                        }
                        struct __Visitor<'de> {
                            marker: _serde::export::PhantomData<Proof>,
                            lifetime: _serde::export::PhantomData<&'de ()>,
                        }
                        impl <'de> _serde::de::Visitor<'de> for __Visitor<'de>
                         {
                            type
                            Value
                            =
                            Proof;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "struct Proof")
                            }
                            #[inline]
                            fn visit_seq<__A>(self, mut __seq: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::SeqAccess<'de> {
                                let __field0 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(0usize,
                                                                                                         &"struct Proof with 2 elements"));
                                        }
                                    };
                                let __field1 =
                                    match match _serde::de::SeqAccess::next_element::<Responses>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(1usize,
                                                                                                         &"struct Proof with 2 elements"));
                                        }
                                    };
                                _serde::export::Ok(Proof{challenge: __field0,
                                                         responses:
                                                             __field1,})
                            }
                            #[inline]
                            fn visit_map<__A>(self, mut __map: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::MapAccess<'de> {
                                let mut __field0:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                let mut __field1:
                                        _serde::export::Option<Responses> =
                                    _serde::export::None;
                                while let _serde::export::Some(__key) =
                                          match _serde::de::MapAccess::next_key::<__Field>(&mut __map)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                    match __key {
                                        __Field::__field0 => {
                                            if _serde::export::Option::is_some(&__field0)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("challenge"));
                                            }
                                            __field0 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        __Field::__field1 => {
                                            if _serde::export::Option::is_some(&__field1)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("responses"));
                                            }
                                            __field1 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Responses>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        _ => {
                                            let _ =
                                                match _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(&mut __map)
                                                    {
                                                    _serde::export::Ok(__val)
                                                    => __val,
                                                    _serde::export::Err(__err)
                                                    => {
                                                        return _serde::export::Err(__err);
                                                    }
                                                };
                                        }
                                    }
                                }
                                let __field0 =
                                    match __field0 {
                                        _serde::export::Some(__field0) =>
                                        __field0,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("challenge")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field1 =
                                    match __field1 {
                                        _serde::export::Some(__field1) =>
                                        __field1,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("responses")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Proof{challenge: __field0,
                                                         responses:
                                                             __field1,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["challenge", "responses"];
                        _serde::Deserializer::deserialize_struct(__deserializer,
                                                                 "Proof",
                                                                 FIELDS,
                                                                 __Visitor{marker:
                                                                               _serde::export::PhantomData::<Proof>,
                                                                           lifetime:
                                                                               _serde::export::PhantomData,})
                    }
                }
            };
        impl Proof {
            /// Create a `Proof` from the given `Publics` and `Secrets`.
            #[allow(dead_code)]
            pub fn create(transcript: &mut Transcript, publics: Publics,
                          secrets: Secrets) -> Proof {
                transcript.commit_bytes(b"domain-sep",
                                        "_blind_attributes".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("D".as_bytes(),
                                        publics.D.compress().as_bytes());
                transcript.commit_bytes("roster_entry".as_bytes(),
                                        publics.roster_entry.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_0".as_bytes(),
                                        publics.encrypted_attribute_0_0.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_1".as_bytes(),
                                        publics.encrypted_attribute_0_1.compress().as_bytes());
                let rng_ctor = transcript.fork_transcript();
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("d".as_bytes(),
                                                  secrets.d.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("e0".as_bytes(),
                                                  secrets.e0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("m0".as_bytes(),
                                                  secrets.m0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("nonce".as_bytes(),
                                                  secrets.nonce.as_bytes());
                let mut transcript_rng =
                    rng_ctor.reseed_from_rng(&mut thread_rng());
                let rand =
                    Randomnesses{d: Scalar::random(&mut transcript_rng),
                                 e0: Scalar::random(&mut transcript_rng),
                                 m0: Scalar::random(&mut transcript_rng),
                                 nonce: Scalar::random(&mut transcript_rng),};
                let commitments =
                    Commitments{D:
                                    RistrettoPoint::multiscalar_mul(&[rand.d],
                                                                    &[*(publics.B)]),
                                encrypted_attribute_0_0:
                                    RistrettoPoint::multiscalar_mul(&[rand.e0],
                                                                    &[*(publics.B)]),
                                encrypted_attribute_0_1:
                                    RistrettoPoint::multiscalar_mul(&[rand.m0,
                                                                      rand.e0],
                                                                    &[*(publics.B),
                                                                      *(publics.D)]),
                                roster_entry:
                                    RistrettoPoint::multiscalar_mul(&[rand.m0,
                                                                      rand.nonce],
                                                                    &[*(publics.A),
                                                                      *(publics.B)]),};
                transcript.commit_bytes("com D".as_bytes(),
                                        commitments.D.compress().as_bytes());
                transcript.commit_bytes("com encrypted_attribute_0_0".as_bytes(),
                                        commitments.encrypted_attribute_0_0.compress().as_bytes());
                transcript.commit_bytes("com encrypted_attribute_0_1".as_bytes(),
                                        commitments.encrypted_attribute_0_1.compress().as_bytes());
                transcript.commit_bytes("com roster_entry".as_bytes(),
                                        commitments.roster_entry.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                let responses =
                    Responses{d: &(&challenge * secrets.d) + &rand.d,
                              e0: &(&challenge * secrets.e0) + &rand.e0,
                              m0: &(&challenge * secrets.m0) + &rand.m0,
                              nonce:
                                  &(&challenge * secrets.nonce) +
                                      &rand.nonce,};
                Proof{challenge: challenge, responses: responses,}
            }
            /// Verify the `Proof` using the public parameters `Publics`.
            #[allow(dead_code)]
            pub fn verify(&self, transcript: &mut Transcript,
                          publics: Publics) -> Result<(), ()> {
                let responses = &self.responses;
                let minus_c = -&self.challenge;
                let commitments =
                    Commitments{D:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.d]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.B)]).into_iter().chain(iter::once(publics.D))),
                                encrypted_attribute_0_0:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.e0]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.B)]).into_iter().chain(iter::once(publics.encrypted_attribute_0_0))),
                                encrypted_attribute_0_1:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.m0,
                                                                               responses.e0]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.B),
                                                                               *(publics.D)]).into_iter().chain(iter::once(publics.encrypted_attribute_0_1))),
                                roster_entry:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.m0,
                                                                               responses.nonce]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.A),
                                                                               *(publics.B)]).into_iter().chain(iter::once(publics.roster_entry))),};
                transcript.commit_bytes(b"domain-sep",
                                        "_blind_attributes".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("D".as_bytes(),
                                        publics.D.compress().as_bytes());
                transcript.commit_bytes("roster_entry".as_bytes(),
                                        publics.roster_entry.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_0".as_bytes(),
                                        publics.encrypted_attribute_0_0.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_1".as_bytes(),
                                        publics.encrypted_attribute_0_1.compress().as_bytes());
                transcript.commit_bytes("com D".as_bytes(),
                                        commitments.D.compress().as_bytes());
                transcript.commit_bytes("com encrypted_attribute_0_0".as_bytes(),
                                        commitments.encrypted_attribute_0_0.compress().as_bytes());
                transcript.commit_bytes("com encrypted_attribute_0_1".as_bytes(),
                                        commitments.encrypted_attribute_0_1.compress().as_bytes());
                transcript.commit_bytes("com roster_entry".as_bytes(),
                                        commitments.roster_entry.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                if challenge == self.challenge { Ok(()) } else { Err(()) }
            }
        }
    }
    pub mod revealed_attributes {
        use ::curve25519_dalek::scalar::Scalar;
        use ::curve25519_dalek::ristretto::RistrettoPoint;
        use ::curve25519_dalek::traits::{MultiscalarMul,
                                         VartimeMultiscalarMul};
        use ::merlin::Transcript;
        use ::rand::thread_rng;
        #[cfg(not(feature = "std"))]
        use core::iter;
        #[rustc_copy_clone_marker]
        pub struct Secrets<'a> {
            pub nonce: &'a Scalar,
            pub phone_number: &'a Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::marker::Copy for Secrets<'a> { }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::clone::Clone for Secrets<'a> {
            #[inline]
            fn clone(&self) -> Secrets<'a> {
                {
                    let _: ::core::clone::AssertParamIsClone<&'a Scalar>;
                    let _: ::core::clone::AssertParamIsClone<&'a Scalar>;
                    *self
                }
            }
        }
        #[rustc_copy_clone_marker]
        pub struct Publics<'a> {
            pub g: &'a RistrettoPoint,
            pub h: &'a RistrettoPoint,
            pub roster_entry_commitment_number: &'a RistrettoPoint,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::marker::Copy for Publics<'a> { }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl <'a> ::core::clone::Clone for Publics<'a> {
            #[inline]
            fn clone(&self) -> Publics<'a> {
                {
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    let _:
                            ::core::clone::AssertParamIsClone<&'a RistrettoPoint>;
                    *self
                }
            }
        }
        struct Commitments {
            roster_entry_commitment_number: RistrettoPoint,
        }
        struct Randomnesses {
            nonce: Scalar,
            phone_number: Scalar,
        }
        #[structural_match]
        struct Responses {
            nonce: Scalar,
            phone_number: Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for Responses {
            #[inline]
            fn clone(&self) -> Responses {
                match *self {
                    Responses {
                    nonce: ref __self_0_0, phone_number: ref __self_0_1 } =>
                    Responses{nonce:
                                  ::core::clone::Clone::clone(&(*__self_0_0)),
                              phone_number:
                                  ::core::clone::Clone::clone(&(*__self_0_1)),},
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::fmt::Debug for Responses {
            fn fmt(&self, f: &mut ::core::fmt::Formatter)
             -> ::core::fmt::Result {
                match *self {
                    Responses {
                    nonce: ref __self_0_0, phone_number: ref __self_0_1 } => {
                        let mut debug_trait_builder =
                            f.debug_struct("Responses");
                        let _ =
                            debug_trait_builder.field("nonce",
                                                      &&(*__self_0_0));
                        let _ =
                            debug_trait_builder.field("phone_number",
                                                      &&(*__self_0_1));
                        debug_trait_builder.finish()
                    }
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::Eq for Responses {
            #[inline]
            #[doc(hidden)]
            fn assert_receiver_is_total_eq(&self) -> () {
                {
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::PartialEq for Responses {
            #[inline]
            fn eq(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    nonce: ref __self_1_0, phone_number: ref __self_1_1 } =>
                    match *self {
                        Responses {
                        nonce: ref __self_0_0, phone_number: ref __self_0_1 }
                        =>
                        (*__self_0_0) == (*__self_1_0) &&
                            (*__self_0_1) == (*__self_1_1),
                    },
                }
            }
            #[inline]
            fn ne(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    nonce: ref __self_1_0, phone_number: ref __self_1_1 } =>
                    match *self {
                        Responses {
                        nonce: ref __self_0_0, phone_number: ref __self_0_1 }
                        =>
                        (*__self_0_0) != (*__self_1_0) ||
                            (*__self_0_1) != (*__self_1_1),
                    },
                }
            }
        }
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_SERIALIZE_FOR_Responses: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl _serde::Serialize for Responses {
                    fn serialize<__S>(&self, __serializer: __S)
                     -> _serde::export::Result<__S::Ok, __S::Error> where
                     __S: _serde::Serializer {
                        let mut __serde_state =
                            match _serde::Serializer::serialize_struct(__serializer,
                                                                       "Responses",
                                                                       0 + 1 +
                                                                           1)
                                {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "nonce",
                                                                            &self.nonce)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "phone_number",
                                                                            &self.phone_number)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_DESERIALIZE_FOR_Responses: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl <'de> _serde::Deserialize<'de> for Responses {
                    fn deserialize<__D>(__deserializer: __D)
                     -> _serde::export::Result<Self, __D::Error> where
                     __D: _serde::Deserializer<'de> {
                        #[allow(non_camel_case_types)]
                        enum __Field { __field0, __field1, __ignore, }
                        struct __FieldVisitor;
                        impl <'de> _serde::de::Visitor<'de> for __FieldVisitor
                         {
                            type
                            Value
                            =
                            __Field;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "field identifier")
                            }
                            fn visit_u64<__E>(self, __value: u64)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    0u64 =>
                                    _serde::export::Ok(__Field::__field0),
                                    1u64 =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ =>
                                    _serde::export::Err(_serde::de::Error::invalid_value(_serde::de::Unexpected::Unsigned(__value),
                                                                                         &"field index 0 <= i < 2")),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    "nonce" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "phone_number" =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8])
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    b"nonce" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"phone_number" =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                        }
                        impl <'de> _serde::Deserialize<'de> for __Field {
                            #[inline]
                            fn deserialize<__D>(__deserializer: __D)
                             -> _serde::export::Result<Self, __D::Error> where
                             __D: _serde::Deserializer<'de> {
                                _serde::Deserializer::deserialize_identifier(__deserializer,
                                                                             __FieldVisitor)
                            }
                        }
                        struct __Visitor<'de> {
                            marker: _serde::export::PhantomData<Responses>,
                            lifetime: _serde::export::PhantomData<&'de ()>,
                        }
                        impl <'de> _serde::de::Visitor<'de> for __Visitor<'de>
                         {
                            type
                            Value
                            =
                            Responses;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "struct Responses")
                            }
                            #[inline]
                            fn visit_seq<__A>(self, mut __seq: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::SeqAccess<'de> {
                                let __field0 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(0usize,
                                                                                                         &"struct Responses with 2 elements"));
                                        }
                                    };
                                let __field1 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(1usize,
                                                                                                         &"struct Responses with 2 elements"));
                                        }
                                    };
                                _serde::export::Ok(Responses{nonce: __field0,
                                                             phone_number:
                                                                 __field1,})
                            }
                            #[inline]
                            fn visit_map<__A>(self, mut __map: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::MapAccess<'de> {
                                let mut __field0:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                let mut __field1:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                while let _serde::export::Some(__key) =
                                          match _serde::de::MapAccess::next_key::<__Field>(&mut __map)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                    match __key {
                                        __Field::__field0 => {
                                            if _serde::export::Option::is_some(&__field0)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("nonce"));
                                            }
                                            __field0 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        __Field::__field1 => {
                                            if _serde::export::Option::is_some(&__field1)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("phone_number"));
                                            }
                                            __field1 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        _ => {
                                            let _ =
                                                match _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(&mut __map)
                                                    {
                                                    _serde::export::Ok(__val)
                                                    => __val,
                                                    _serde::export::Err(__err)
                                                    => {
                                                        return _serde::export::Err(__err);
                                                    }
                                                };
                                        }
                                    }
                                }
                                let __field0 =
                                    match __field0 {
                                        _serde::export::Some(__field0) =>
                                        __field0,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("nonce")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field1 =
                                    match __field1 {
                                        _serde::export::Some(__field1) =>
                                        __field1,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("phone_number")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Responses{nonce: __field0,
                                                             phone_number:
                                                                 __field1,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["nonce", "phone_number"];
                        _serde::Deserializer::deserialize_struct(__deserializer,
                                                                 "Responses",
                                                                 FIELDS,
                                                                 __Visitor{marker:
                                                                               _serde::export::PhantomData::<Responses>,
                                                                           lifetime:
                                                                               _serde::export::PhantomData,})
                    }
                }
            };
        #[structural_match]
        pub struct Proof {
            challenge: Scalar,
            responses: Responses,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for Proof {
            #[inline]
            fn clone(&self) -> Proof {
                match *self {
                    Proof {
                    challenge: ref __self_0_0, responses: ref __self_0_1 } =>
                    Proof{challenge:
                              ::core::clone::Clone::clone(&(*__self_0_0)),
                          responses:
                              ::core::clone::Clone::clone(&(*__self_0_1)),},
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::fmt::Debug for Proof {
            fn fmt(&self, f: &mut ::core::fmt::Formatter)
             -> ::core::fmt::Result {
                match *self {
                    Proof {
                    challenge: ref __self_0_0, responses: ref __self_0_1 } =>
                    {
                        let mut debug_trait_builder = f.debug_struct("Proof");
                        let _ =
                            debug_trait_builder.field("challenge",
                                                      &&(*__self_0_0));
                        let _ =
                            debug_trait_builder.field("responses",
                                                      &&(*__self_0_1));
                        debug_trait_builder.finish()
                    }
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::Eq for Proof {
            #[inline]
            #[doc(hidden)]
            fn assert_receiver_is_total_eq(&self) -> () {
                {
                    let _: ::core::cmp::AssertParamIsEq<Scalar>;
                    let _: ::core::cmp::AssertParamIsEq<Responses>;
                }
            }
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::PartialEq for Proof {
            #[inline]
            fn eq(&self, other: &Proof) -> bool {
                match *other {
                    Proof {
                    challenge: ref __self_1_0, responses: ref __self_1_1 } =>
                    match *self {
                        Proof {
                        challenge: ref __self_0_0, responses: ref __self_0_1 }
                        =>
                        (*__self_0_0) == (*__self_1_0) &&
                            (*__self_0_1) == (*__self_1_1),
                    },
                }
            }
            #[inline]
            fn ne(&self, other: &Proof) -> bool {
                match *other {
                    Proof {
                    challenge: ref __self_1_0, responses: ref __self_1_1 } =>
                    match *self {
                        Proof {
                        challenge: ref __self_0_0, responses: ref __self_0_1 }
                        =>
                        (*__self_0_0) != (*__self_1_0) ||
                            (*__self_0_1) != (*__self_1_1),
                    },
                }
            }
        }
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_SERIALIZE_FOR_Proof: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl _serde::Serialize for Proof {
                    fn serialize<__S>(&self, __serializer: __S)
                     -> _serde::export::Result<__S::Ok, __S::Error> where
                     __S: _serde::Serializer {
                        let mut __serde_state =
                            match _serde::Serializer::serialize_struct(__serializer,
                                                                       "Proof",
                                                                       0 + 1 +
                                                                           1)
                                {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "challenge",
                                                                            &self.challenge)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "responses",
                                                                            &self.responses)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
        #[allow(non_upper_case_globals,
                unused_attributes,
                unused_qualifications)]
        const _IMPL_DESERIALIZE_FOR_Proof: () =
            {
                #[allow(unknown_lints)]
                #[allow(rust_2018_idioms)]
                extern crate serde as _serde;
                #[allow(unused_macros)]
                macro_rules! try(( $ __expr : expr ) => {
                                 match $ __expr {
                                 _serde :: export :: Ok ( __val ) => __val ,
                                 _serde :: export :: Err ( __err ) => {
                                 return _serde :: export :: Err ( __err ) ; }
                                 } });
                #[automatically_derived]
                impl <'de> _serde::Deserialize<'de> for Proof {
                    fn deserialize<__D>(__deserializer: __D)
                     -> _serde::export::Result<Self, __D::Error> where
                     __D: _serde::Deserializer<'de> {
                        #[allow(non_camel_case_types)]
                        enum __Field { __field0, __field1, __ignore, }
                        struct __FieldVisitor;
                        impl <'de> _serde::de::Visitor<'de> for __FieldVisitor
                         {
                            type
                            Value
                            =
                            __Field;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "field identifier")
                            }
                            fn visit_u64<__E>(self, __value: u64)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    0u64 =>
                                    _serde::export::Ok(__Field::__field0),
                                    1u64 =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ =>
                                    _serde::export::Err(_serde::de::Error::invalid_value(_serde::de::Unexpected::Unsigned(__value),
                                                                                         &"field index 0 <= i < 2")),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    "challenge" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "responses" =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8])
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    b"challenge" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"responses" =>
                                    _serde::export::Ok(__Field::__field1),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                        }
                        impl <'de> _serde::Deserialize<'de> for __Field {
                            #[inline]
                            fn deserialize<__D>(__deserializer: __D)
                             -> _serde::export::Result<Self, __D::Error> where
                             __D: _serde::Deserializer<'de> {
                                _serde::Deserializer::deserialize_identifier(__deserializer,
                                                                             __FieldVisitor)
                            }
                        }
                        struct __Visitor<'de> {
                            marker: _serde::export::PhantomData<Proof>,
                            lifetime: _serde::export::PhantomData<&'de ()>,
                        }
                        impl <'de> _serde::de::Visitor<'de> for __Visitor<'de>
                         {
                            type
                            Value
                            =
                            Proof;
                            fn expecting(&self,
                                         __formatter:
                                             &mut _serde::export::Formatter)
                             -> _serde::export::fmt::Result {
                                _serde::export::Formatter::write_str(__formatter,
                                                                     "struct Proof")
                            }
                            #[inline]
                            fn visit_seq<__A>(self, mut __seq: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::SeqAccess<'de> {
                                let __field0 =
                                    match match _serde::de::SeqAccess::next_element::<Scalar>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(0usize,
                                                                                                         &"struct Proof with 2 elements"));
                                        }
                                    };
                                let __field1 =
                                    match match _serde::de::SeqAccess::next_element::<Responses>(&mut __seq)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                        _serde::export::Some(__value) =>
                                        __value,
                                        _serde::export::None => {
                                            return _serde::export::Err(_serde::de::Error::invalid_length(1usize,
                                                                                                         &"struct Proof with 2 elements"));
                                        }
                                    };
                                _serde::export::Ok(Proof{challenge: __field0,
                                                         responses:
                                                             __field1,})
                            }
                            #[inline]
                            fn visit_map<__A>(self, mut __map: __A)
                             ->
                                 _serde::export::Result<Self::Value,
                                                        __A::Error> where
                             __A: _serde::de::MapAccess<'de> {
                                let mut __field0:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                let mut __field1:
                                        _serde::export::Option<Responses> =
                                    _serde::export::None;
                                while let _serde::export::Some(__key) =
                                          match _serde::de::MapAccess::next_key::<__Field>(&mut __map)
                                              {
                                              _serde::export::Ok(__val) =>
                                              __val,
                                              _serde::export::Err(__err) => {
                                                  return _serde::export::Err(__err);
                                              }
                                          } {
                                    match __key {
                                        __Field::__field0 => {
                                            if _serde::export::Option::is_some(&__field0)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("challenge"));
                                            }
                                            __field0 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Scalar>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        __Field::__field1 => {
                                            if _serde::export::Option::is_some(&__field1)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("responses"));
                                            }
                                            __field1 =
                                                _serde::export::Some(match _serde::de::MapAccess::next_value::<Responses>(&mut __map)
                                                                         {
                                                                         _serde::export::Ok(__val)
                                                                         =>
                                                                         __val,
                                                                         _serde::export::Err(__err)
                                                                         => {
                                                                             return _serde::export::Err(__err);
                                                                         }
                                                                     });
                                        }
                                        _ => {
                                            let _ =
                                                match _serde::de::MapAccess::next_value::<_serde::de::IgnoredAny>(&mut __map)
                                                    {
                                                    _serde::export::Ok(__val)
                                                    => __val,
                                                    _serde::export::Err(__err)
                                                    => {
                                                        return _serde::export::Err(__err);
                                                    }
                                                };
                                        }
                                    }
                                }
                                let __field0 =
                                    match __field0 {
                                        _serde::export::Some(__field0) =>
                                        __field0,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("challenge")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field1 =
                                    match __field1 {
                                        _serde::export::Some(__field1) =>
                                        __field1,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("responses")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Proof{challenge: __field0,
                                                         responses:
                                                             __field1,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["challenge", "responses"];
                        _serde::Deserializer::deserialize_struct(__deserializer,
                                                                 "Proof",
                                                                 FIELDS,
                                                                 __Visitor{marker:
                                                                               _serde::export::PhantomData::<Proof>,
                                                                           lifetime:
                                                                               _serde::export::PhantomData,})
                    }
                }
            };
        impl Proof {
            /// Create a `Proof` from the given `Publics` and `Secrets`.
            #[allow(dead_code)]
            pub fn create(transcript: &mut Transcript, publics: Publics,
                          secrets: Secrets) -> Proof {
                transcript.commit_bytes(b"domain-sep",
                                        "revealed_attributes".as_bytes());
                transcript.commit_bytes("g".as_bytes(),
                                        publics.g.compress().as_bytes());
                transcript.commit_bytes("h".as_bytes(),
                                        publics.h.compress().as_bytes());
                transcript.commit_bytes("roster_entry_commitment_number".as_bytes(),
                                        publics.roster_entry_commitment_number.compress().as_bytes());
                let rng_ctor = transcript.fork_transcript();
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("nonce".as_bytes(),
                                                  secrets.nonce.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("phone_number".as_bytes(),
                                                  secrets.phone_number.as_bytes());
                let mut transcript_rng =
                    rng_ctor.reseed_from_rng(&mut thread_rng());
                let rand =
                    Randomnesses{nonce: Scalar::random(&mut transcript_rng),
                                 phone_number:
                                     Scalar::random(&mut transcript_rng),};
                let commitments =
                    Commitments{roster_entry_commitment_number:
                                    RistrettoPoint::multiscalar_mul(&[rand.phone_number,
                                                                      rand.nonce],
                                                                    &[*(publics.h),
                                                                      *(publics.g)]),};
                transcript.commit_bytes("com roster_entry_commitment_number".as_bytes(),
                                        commitments.roster_entry_commitment_number.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                let responses =
                    Responses{nonce:
                                  &(&challenge * secrets.nonce) + &rand.nonce,
                              phone_number:
                                  &(&challenge * secrets.phone_number) +
                                      &rand.phone_number,};
                Proof{challenge: challenge, responses: responses,}
            }
            /// Verify the `Proof` using the public parameters `Publics`.
            #[allow(dead_code)]
            pub fn verify(&self, transcript: &mut Transcript,
                          publics: Publics) -> Result<(), ()> {
                let responses = &self.responses;
                let minus_c = -&self.challenge;
                let commitments =
                    Commitments{roster_entry_commitment_number:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.phone_number,
                                                                               responses.nonce]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.h),
                                                                               *(publics.g)]).into_iter().chain(iter::once(publics.roster_entry_commitment_number))),};
                transcript.commit_bytes(b"domain-sep",
                                        "revealed_attributes".as_bytes());
                transcript.commit_bytes("g".as_bytes(),
                                        publics.g.compress().as_bytes());
                transcript.commit_bytes("h".as_bytes(),
                                        publics.h.compress().as_bytes());
                transcript.commit_bytes("roster_entry_commitment_number".as_bytes(),
                                        publics.roster_entry_commitment_number.compress().as_bytes());
                transcript.commit_bytes("com roster_entry_commitment_number".as_bytes(),
                                        commitments.roster_entry_commitment_number.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                if challenge == self.challenge { Ok(()) } else { Err(()) }
            }
        }
    }
}
