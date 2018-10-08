// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![no_std]

//! Zero-knowledge proofs.
//!
//! # Note
//!
//! The notation and variable names used throughout this module are that of
//! [LdV'17](https://patternsinthevoid.net/hyphae/hyphae.pdf), not those of
//! [CMZ'13](https://eprint.iacr.org/2013/516.pdf) because the latter was
//! missing signification details of the construction.

#[cfg(any(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate zkp;

pub mod proofs {

    pub mod issuance_revealed {
        use ::curve25519_dalek::scalar::Scalar;
        use ::curve25519_dalek::ristretto::RistrettoPoint;
        use ::curve25519_dalek::traits::{MultiscalarMul,
                                         VartimeMultiscalarMul};
        use ::merlin::Transcript;
        use ::rand::thread_rng;

        #[cfg(not(feature = "std"))]
        use core::iter;

        #[derive(Clone, Copy)]
        pub struct Secrets<'a> {
            pub x0: &'a Scalar,
            pub x1: &'a Scalar,
            pub x0_tilde: &'a Scalar,
            pub m1x1: &'a Scalar,
        }

        #[derive(Clone, Copy)]
        pub struct Publics<'a> {
            pub P: &'a RistrettoPoint,
            pub Q: &'a RistrettoPoint,
            pub Cx0: &'a RistrettoPoint,
            pub B: &'a RistrettoPoint,
            pub A: &'a RistrettoPoint,
            pub X1: &'a RistrettoPoint,
        }

        struct Commitments {
            Q: RistrettoPoint,
            Cx0: RistrettoPoint,
            X1: RistrettoPoint,
        }

        struct Randomnesses {
            x0: Scalar,
            x1: Scalar,
            x0_tilde: Scalar,
            m1x1: Scalar,
        }

        #[derive(Clone, Copy, Debug, Eq)]
        struct Responses {
            x0: Scalar,
            x1: Scalar,
            x0_tilde: Scalar,
            m1x1: Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::cmp::PartialEq for Responses {
            #[inline]
            fn eq(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    x0: ref __self_1_0,
                    x1: ref __self_1_1,
                    x0_tilde: ref __self_1_2,
                    m1x1: ref __self_1_3 } =>
                    match *self {
                        Responses {
                        x0: ref __self_0_0,
                        x1: ref __self_0_1,
                        x0_tilde: ref __self_0_2,
                        m1x1: ref __self_0_3 } =>
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
                    x0: ref __self_1_0,
                    x1: ref __self_1_1,
                    x0_tilde: ref __self_1_2,
                    m1x1: ref __self_1_3 } =>
                    match *self {
                        Responses {
                        x0: ref __self_0_0,
                        x1: ref __self_0_1,
                        x0_tilde: ref __self_0_2,
                        m1x1: ref __self_0_3 } =>
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
                                                                            "x0",
                                                                            &self.x0)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "x1",
                                                                            &self.x1)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "x0_tilde",
                                                                            &self.x0_tilde)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "m1x1",
                                                                            &self.m1x1)
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
                                    "x0" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "x1" =>
                                    _serde::export::Ok(__Field::__field1),
                                    "x0_tilde" =>
                                    _serde::export::Ok(__Field::__field2),
                                    "m1x1" =>
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
                                    b"x0" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"x1" =>
                                    _serde::export::Ok(__Field::__field1),
                                    b"x0_tilde" =>
                                    _serde::export::Ok(__Field::__field2),
                                    b"m1x1" =>
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
                                _serde::export::Ok(Responses{x0: __field0,
                                                             x1: __field1,
                                                             x0_tilde:
                                                                 __field2,
                                                             m1x1: __field3,})
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
                                                                               _serde::de::Error>::duplicate_field("x0"));
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
                                                                               _serde::de::Error>::duplicate_field("x1"));
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
                                                                               _serde::de::Error>::duplicate_field("x0_tilde"));
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
                                                                               _serde::de::Error>::duplicate_field("m1x1"));
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
                                        match _serde::private::de::missing_field("x0")
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
                                        match _serde::private::de::missing_field("x1")
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
                                        match _serde::private::de::missing_field("x0_tilde")
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
                                        match _serde::private::de::missing_field("m1x1")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Responses{x0: __field0,
                                                             x1: __field1,
                                                             x0_tilde:
                                                                 __field2,
                                                             m1x1: __field3,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["x0", "x1", "x0_tilde", "m1x1"];
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
                                        "issuance_revealed".as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("Q".as_bytes(),
                                        publics.Q.compress().as_bytes());
                transcript.commit_bytes("Cx0".as_bytes(),
                                        publics.Cx0.compress().as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("X1".as_bytes(),
                                        publics.X1.compress().as_bytes());
                let rng_ctor = transcript.fork_transcript();
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("x0".as_bytes(),
                                                  secrets.x0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("x1".as_bytes(),
                                                  secrets.x1.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("x0_tilde".as_bytes(),
                                                  secrets.x0_tilde.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("m1x1".as_bytes(),
                                                  secrets.m1x1.as_bytes());
                let mut transcript_rng =
                    rng_ctor.reseed_from_rng(&mut thread_rng());
                let rand =
                    Randomnesses{x0: Scalar::random(&mut transcript_rng),
                                 x1: Scalar::random(&mut transcript_rng),
                                 x0_tilde:
                                     Scalar::random(&mut transcript_rng),
                                 m1x1: Scalar::random(&mut transcript_rng),};
                let commitments =
                    Commitments{Q:
                                    RistrettoPoint::multiscalar_mul(&[rand.x0,
                                                                      rand.m1x1],
                                                                    &[*(publics.P),
                                                                      *(publics.P)]),
                                Cx0:
                                    RistrettoPoint::multiscalar_mul(&[rand.x0,
                                                                      rand.x0_tilde],
                                                                    &[*(publics.B),
                                                                      *(publics.A)]),
                                X1:
                                    RistrettoPoint::multiscalar_mul(&[rand.x1],
                                                                    &[*(publics.A)]),};
                transcript.commit_bytes("com Q".as_bytes(),
                                        commitments.Q.compress().as_bytes());
                transcript.commit_bytes("com Cx0".as_bytes(),
                                        commitments.Cx0.compress().as_bytes());
                transcript.commit_bytes("com X1".as_bytes(),
                                        commitments.X1.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                let responses =
                    Responses{x0: &(&challenge * secrets.x0) + &rand.x0,
                              x1: &(&challenge * secrets.x1) + &rand.x1,
                              x0_tilde:
                                  &(&challenge * secrets.x0_tilde) +
                                      &rand.x0_tilde,
                              m1x1:
                                  &(&challenge * secrets.m1x1) + &rand.m1x1,};
                Proof{challenge: challenge, responses: responses,}
            }
            /// Verify the `Proof` using the public parameters `Publics`.
            #[allow(dead_code)]
            pub fn verify(&self, transcript: &mut Transcript,
                          publics: Publics) -> Result<(), ()> {
                let responses = &self.responses;
                let minus_c = -&self.challenge;
                let commitments =
                    Commitments{Q:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.x0,
                                                                               responses.m1x1]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.P),
                                                                               *(publics.P)]).into_iter().chain(iter::once(publics.Q))),
                                Cx0:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.x0,
                                                                               responses.x0_tilde]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.B),
                                                                               *(publics.A)]).into_iter().chain(iter::once(publics.Cx0))),
                                X1:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.x1]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.A)]).into_iter().chain(iter::once(publics.X1))),};
                transcript.commit_bytes(b"domain-sep",
                                        "issuance_revealed".as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("Q".as_bytes(),
                                        publics.Q.compress().as_bytes());
                transcript.commit_bytes("Cx0".as_bytes(),
                                        publics.Cx0.compress().as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("X1".as_bytes(),
                                        publics.X1.compress().as_bytes());
                transcript.commit_bytes("com Q".as_bytes(),
                                        commitments.Q.compress().as_bytes());
                transcript.commit_bytes("com Cx0".as_bytes(),
                                        commitments.Cx0.compress().as_bytes());
                transcript.commit_bytes("com X1".as_bytes(),
                                        commitments.X1.compress().as_bytes());
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
    pub mod attributes_blinded {
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
                    *self
                }
            }
        }
        struct Commitments {
            D: RistrettoPoint,
            encrypted_attribute_0_0: RistrettoPoint,
            encrypted_attribute_0_1: RistrettoPoint,
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
                                        "attributes_blinded".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("D".as_bytes(),
                                        publics.D.compress().as_bytes());
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
                                                                      *(publics.D)]),};
                transcript.commit_bytes("com D".as_bytes(),
                                        commitments.D.compress().as_bytes());
                transcript.commit_bytes("com encrypted_attribute_0_0".as_bytes(),
                                        commitments.encrypted_attribute_0_0.compress().as_bytes());
                transcript.commit_bytes("com encrypted_attribute_0_1".as_bytes(),
                                        commitments.encrypted_attribute_0_1.compress().as_bytes());
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
                                                                               *(publics.D)]).into_iter().chain(iter::once(publics.encrypted_attribute_0_1))),};
                transcript.commit_bytes(b"domain-sep",
                                        "attributes_blinded".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("D".as_bytes(),
                                        publics.D.compress().as_bytes());
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
    pub mod issuance_blinded {
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
            pub x0_tilde: &'a Scalar,
            pub x0: &'a Scalar,
            pub x1: &'a Scalar,
            pub s: &'a Scalar,
            pub b: &'a Scalar,
            pub t0: &'a Scalar,
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
            pub X0: &'a RistrettoPoint,
            pub X1: &'a RistrettoPoint,
            pub D: &'a RistrettoPoint,
            pub P: &'a RistrettoPoint,
            pub T0_0: &'a RistrettoPoint,
            pub T0_1: &'a RistrettoPoint,
            pub EQ_commitment: &'a RistrettoPoint,
            pub EQ_encryption: &'a RistrettoPoint,
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
            X0: RistrettoPoint,
            X1: RistrettoPoint,
            P: RistrettoPoint,
            T0_0: RistrettoPoint,
            T0_1: RistrettoPoint,
            EQ_commitment: RistrettoPoint,
            EQ_encryption: RistrettoPoint,
        }
        struct Randomnesses {
            x0_tilde: Scalar,
            x0: Scalar,
            x1: Scalar,
            s: Scalar,
            b: Scalar,
            t0: Scalar,
        }
        #[structural_match]
        struct Responses {
            x0_tilde: Scalar,
            x0: Scalar,
            x1: Scalar,
            s: Scalar,
            b: Scalar,
            t0: Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for Responses {
            #[inline]
            fn clone(&self) -> Responses {
                match *self {
                    Responses {
                    x0_tilde: ref __self_0_0,
                    x0: ref __self_0_1,
                    x1: ref __self_0_2,
                    s: ref __self_0_3,
                    b: ref __self_0_4,
                    t0: ref __self_0_5 } =>
                    Responses{x0_tilde:
                                  ::core::clone::Clone::clone(&(*__self_0_0)),
                              x0: ::core::clone::Clone::clone(&(*__self_0_1)),
                              x1: ::core::clone::Clone::clone(&(*__self_0_2)),
                              s: ::core::clone::Clone::clone(&(*__self_0_3)),
                              b: ::core::clone::Clone::clone(&(*__self_0_4)),
                              t0:
                                  ::core::clone::Clone::clone(&(*__self_0_5)),},
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
                    x0_tilde: ref __self_0_0,
                    x0: ref __self_0_1,
                    x1: ref __self_0_2,
                    s: ref __self_0_3,
                    b: ref __self_0_4,
                    t0: ref __self_0_5 } => {
                        let mut debug_trait_builder =
                            f.debug_struct("Responses");
                        let _ =
                            debug_trait_builder.field("x0_tilde",
                                                      &&(*__self_0_0));
                        let _ =
                            debug_trait_builder.field("x0", &&(*__self_0_1));
                        let _ =
                            debug_trait_builder.field("x1", &&(*__self_0_2));
                        let _ =
                            debug_trait_builder.field("s", &&(*__self_0_3));
                        let _ =
                            debug_trait_builder.field("b", &&(*__self_0_4));
                        let _ =
                            debug_trait_builder.field("t0", &&(*__self_0_5));
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
                    x0_tilde: ref __self_1_0,
                    x0: ref __self_1_1,
                    x1: ref __self_1_2,
                    s: ref __self_1_3,
                    b: ref __self_1_4,
                    t0: ref __self_1_5 } =>
                    match *self {
                        Responses {
                        x0_tilde: ref __self_0_0,
                        x0: ref __self_0_1,
                        x1: ref __self_0_2,
                        s: ref __self_0_3,
                        b: ref __self_0_4,
                        t0: ref __self_0_5 } =>
                        (*__self_0_0) == (*__self_1_0) &&
                            (*__self_0_1) == (*__self_1_1) &&
                            (*__self_0_2) == (*__self_1_2) &&
                            (*__self_0_3) == (*__self_1_3) &&
                            (*__self_0_4) == (*__self_1_4) &&
                            (*__self_0_5) == (*__self_1_5),
                    },
                }
            }
            #[inline]
            fn ne(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    x0_tilde: ref __self_1_0,
                    x0: ref __self_1_1,
                    x1: ref __self_1_2,
                    s: ref __self_1_3,
                    b: ref __self_1_4,
                    t0: ref __self_1_5 } =>
                    match *self {
                        Responses {
                        x0_tilde: ref __self_0_0,
                        x0: ref __self_0_1,
                        x1: ref __self_0_2,
                        s: ref __self_0_3,
                        b: ref __self_0_4,
                        t0: ref __self_0_5 } =>
                        (*__self_0_0) != (*__self_1_0) ||
                            (*__self_0_1) != (*__self_1_1) ||
                            (*__self_0_2) != (*__self_1_2) ||
                            (*__self_0_3) != (*__self_1_3) ||
                            (*__self_0_4) != (*__self_1_4) ||
                            (*__self_0_5) != (*__self_1_5),
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
                                                                            "x0_tilde",
                                                                            &self.x0_tilde)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "x0",
                                                                            &self.x0)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "x1",
                                                                            &self.x1)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "s",
                                                                            &self.s)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "b",
                                                                            &self.b)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "t0",
                                                                            &self.t0)
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
                            __field4,
                            __field5,
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
                                    4u64 =>
                                    _serde::export::Ok(__Field::__field4),
                                    5u64 =>
                                    _serde::export::Ok(__Field::__field5),
                                    _ =>
                                    _serde::export::Err(_serde::de::Error::invalid_value(_serde::de::Unexpected::Unsigned(__value),
                                                                                         &"field index 0 <= i < 6")),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    "x0_tilde" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "x0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    "x1" =>
                                    _serde::export::Ok(__Field::__field2),
                                    "s" =>
                                    _serde::export::Ok(__Field::__field3),
                                    "b" =>
                                    _serde::export::Ok(__Field::__field4),
                                    "t0" =>
                                    _serde::export::Ok(__Field::__field5),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8])
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    b"x0_tilde" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"x0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    b"x1" =>
                                    _serde::export::Ok(__Field::__field2),
                                    b"s" =>
                                    _serde::export::Ok(__Field::__field3),
                                    b"b" =>
                                    _serde::export::Ok(__Field::__field4),
                                    b"t0" =>
                                    _serde::export::Ok(__Field::__field5),
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
                                                                                                         &"struct Responses with 6 elements"));
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
                                                                                                         &"struct Responses with 6 elements"));
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
                                                                                                         &"struct Responses with 6 elements"));
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
                                                                                                         &"struct Responses with 6 elements"));
                                        }
                                    };
                                let __field4 =
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
                                            return _serde::export::Err(_serde::de::Error::invalid_length(4usize,
                                                                                                         &"struct Responses with 6 elements"));
                                        }
                                    };
                                let __field5 =
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
                                            return _serde::export::Err(_serde::de::Error::invalid_length(5usize,
                                                                                                         &"struct Responses with 6 elements"));
                                        }
                                    };
                                _serde::export::Ok(Responses{x0_tilde:
                                                                 __field0,
                                                             x0: __field1,
                                                             x1: __field2,
                                                             s: __field3,
                                                             b: __field4,
                                                             t0: __field5,})
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
                                let mut __field4:
                                        _serde::export::Option<Scalar> =
                                    _serde::export::None;
                                let mut __field5:
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
                                                                               _serde::de::Error>::duplicate_field("x0_tilde"));
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
                                                                               _serde::de::Error>::duplicate_field("x0"));
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
                                                                               _serde::de::Error>::duplicate_field("x1"));
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
                                                                               _serde::de::Error>::duplicate_field("s"));
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
                                        __Field::__field4 => {
                                            if _serde::export::Option::is_some(&__field4)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("b"));
                                            }
                                            __field4 =
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
                                        __Field::__field5 => {
                                            if _serde::export::Option::is_some(&__field5)
                                               {
                                                return _serde::export::Err(<__A::Error
                                                                               as
                                                                               _serde::de::Error>::duplicate_field("t0"));
                                            }
                                            __field5 =
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
                                        match _serde::private::de::missing_field("x0_tilde")
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
                                        match _serde::private::de::missing_field("x0")
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
                                        match _serde::private::de::missing_field("x1")
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
                                        match _serde::private::de::missing_field("s")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field4 =
                                    match __field4 {
                                        _serde::export::Some(__field4) =>
                                        __field4,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("b")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                let __field5 =
                                    match __field5 {
                                        _serde::export::Some(__field5) =>
                                        __field5,
                                        _serde::export::None =>
                                        match _serde::private::de::missing_field("t0")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Responses{x0_tilde:
                                                                 __field0,
                                                             x0: __field1,
                                                             x1: __field2,
                                                             s: __field3,
                                                             b: __field4,
                                                             t0: __field5,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["x0_tilde", "x0", "x1", "s", "b", "t0"];
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
                                        "issuance_blinded".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("X0".as_bytes(),
                                        publics.X0.compress().as_bytes());
                transcript.commit_bytes("X1".as_bytes(),
                                        publics.X1.compress().as_bytes());
                transcript.commit_bytes("D".as_bytes(),
                                        publics.D.compress().as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("T0_0".as_bytes(),
                                        publics.T0_0.compress().as_bytes());
                transcript.commit_bytes("T0_1".as_bytes(),
                                        publics.T0_1.compress().as_bytes());
                transcript.commit_bytes("EQ_commitment".as_bytes(),
                                        publics.EQ_commitment.compress().as_bytes());
                transcript.commit_bytes("EQ_encryption".as_bytes(),
                                        publics.EQ_encryption.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_0".as_bytes(),
                                        publics.encrypted_attribute_0_0.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_1".as_bytes(),
                                        publics.encrypted_attribute_0_1.compress().as_bytes());
                let rng_ctor = transcript.fork_transcript();
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("x0_tilde".as_bytes(),
                                                  secrets.x0_tilde.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("x0".as_bytes(),
                                                  secrets.x0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("x1".as_bytes(),
                                                  secrets.x1.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("s".as_bytes(),
                                                  secrets.s.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("b".as_bytes(),
                                                  secrets.b.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("t0".as_bytes(),
                                                  secrets.t0.as_bytes());
                let mut transcript_rng =
                    rng_ctor.reseed_from_rng(&mut thread_rng());
                let rand =
                    Randomnesses{x0_tilde:
                                     Scalar::random(&mut transcript_rng),
                                 x0: Scalar::random(&mut transcript_rng),
                                 x1: Scalar::random(&mut transcript_rng),
                                 s: Scalar::random(&mut transcript_rng),
                                 b: Scalar::random(&mut transcript_rng),
                                 t0: Scalar::random(&mut transcript_rng),};
                let commitments =
                    Commitments{X0:
                                    RistrettoPoint::multiscalar_mul(&[rand.x0,
                                                                      rand.x0_tilde],
                                                                    &[*(publics.B),
                                                                      *(publics.A)]),
                                X1:
                                    RistrettoPoint::multiscalar_mul(&[rand.x1],
                                                                    &[*(publics.A)]),
                                P:
                                    RistrettoPoint::multiscalar_mul(&[rand.b],
                                                                    &[*(publics.B)]),
                                T0_0:
                                    RistrettoPoint::multiscalar_mul(&[rand.b],
                                                                    &[*(publics.X0)]),
                                T0_1:
                                    RistrettoPoint::multiscalar_mul(&[rand.t0],
                                                                    &[*(publics.A)]),
                                EQ_commitment:
                                    RistrettoPoint::multiscalar_mul(&[rand.s,
                                                                      rand.t0],
                                                                    &[*(publics.B),
                                                                      *(publics.encrypted_attribute_0_0)]),
                                EQ_encryption:
                                    RistrettoPoint::multiscalar_mul(&[rand.s,
                                                                      rand.t0],
                                                                    &[*(publics.D),
                                                                      *(publics.encrypted_attribute_0_1)]),};
                transcript.commit_bytes("com X0".as_bytes(),
                                        commitments.X0.compress().as_bytes());
                transcript.commit_bytes("com X1".as_bytes(),
                                        commitments.X1.compress().as_bytes());
                transcript.commit_bytes("com P".as_bytes(),
                                        commitments.P.compress().as_bytes());
                transcript.commit_bytes("com T0_0".as_bytes(),
                                        commitments.T0_0.compress().as_bytes());
                transcript.commit_bytes("com T0_1".as_bytes(),
                                        commitments.T0_1.compress().as_bytes());
                transcript.commit_bytes("com EQ_commitment".as_bytes(),
                                        commitments.EQ_commitment.compress().as_bytes());
                transcript.commit_bytes("com EQ_encryption".as_bytes(),
                                        commitments.EQ_encryption.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                let responses =
                    Responses{x0_tilde:
                                  &(&challenge * secrets.x0_tilde) +
                                      &rand.x0_tilde,
                              x0: &(&challenge * secrets.x0) + &rand.x0,
                              x1: &(&challenge * secrets.x1) + &rand.x1,
                              s: &(&challenge * secrets.s) + &rand.s,
                              b: &(&challenge * secrets.b) + &rand.b,
                              t0: &(&challenge * secrets.t0) + &rand.t0,};
                Proof{challenge: challenge, responses: responses,}
            }
            /// Verify the `Proof` using the public parameters `Publics`.
            #[allow(dead_code)]
            pub fn verify(&self, transcript: &mut Transcript,
                          publics: Publics) -> Result<(), ()> {
                let responses = &self.responses;
                let minus_c = -&self.challenge;
                let commitments =
                    Commitments{X0:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.x0,
                                                                               responses.x0_tilde]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.B),
                                                                               *(publics.A)]).into_iter().chain(iter::once(publics.X0))),
                                X1:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.x1]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.A)]).into_iter().chain(iter::once(publics.X1))),
                                P:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.b]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.B)]).into_iter().chain(iter::once(publics.P))),
                                T0_0:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.b]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.X0)]).into_iter().chain(iter::once(publics.T0_0))),
                                T0_1:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.t0]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.A)]).into_iter().chain(iter::once(publics.T0_1))),
                                EQ_commitment:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.s,
                                                                               responses.t0]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.B),
                                                                               *(publics.encrypted_attribute_0_0)]).into_iter().chain(iter::once(publics.EQ_commitment))),
                                EQ_encryption:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.s,
                                                                               responses.t0]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.D),
                                                                               *(publics.encrypted_attribute_0_1)]).into_iter().chain(iter::once(publics.EQ_encryption))),};
                transcript.commit_bytes(b"domain-sep",
                                        "issuance_blinded".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("X0".as_bytes(),
                                        publics.X0.compress().as_bytes());
                transcript.commit_bytes("X1".as_bytes(),
                                        publics.X1.compress().as_bytes());
                transcript.commit_bytes("D".as_bytes(),
                                        publics.D.compress().as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("T0_0".as_bytes(),
                                        publics.T0_0.compress().as_bytes());
                transcript.commit_bytes("T0_1".as_bytes(),
                                        publics.T0_1.compress().as_bytes());
                transcript.commit_bytes("EQ_commitment".as_bytes(),
                                        publics.EQ_commitment.compress().as_bytes());
                transcript.commit_bytes("EQ_encryption".as_bytes(),
                                        publics.EQ_encryption.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_0".as_bytes(),
                                        publics.encrypted_attribute_0_0.compress().as_bytes());
                transcript.commit_bytes("encrypted_attribute_0_1".as_bytes(),
                                        publics.encrypted_attribute_0_1.compress().as_bytes());
                transcript.commit_bytes("com X0".as_bytes(),
                                        commitments.X0.compress().as_bytes());
                transcript.commit_bytes("com X1".as_bytes(),
                                        commitments.X1.compress().as_bytes());
                transcript.commit_bytes("com P".as_bytes(),
                                        commitments.P.compress().as_bytes());
                transcript.commit_bytes("com T0_0".as_bytes(),
                                        commitments.T0_0.compress().as_bytes());
                transcript.commit_bytes("com T0_1".as_bytes(),
                                        commitments.T0_1.compress().as_bytes());
                transcript.commit_bytes("com EQ_commitment".as_bytes(),
                                        commitments.EQ_commitment.compress().as_bytes());
                transcript.commit_bytes("com EQ_encryption".as_bytes(),
                                        commitments.EQ_encryption.compress().as_bytes());
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
    pub mod valid_credential {
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
            pub m0: &'a Scalar,
            pub z0: &'a Scalar,
            pub minus_zQ: &'a Scalar,
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
                    *self
                }
            }
        }
        #[rustc_copy_clone_marker]
        pub struct Publics<'a> {
            pub B: &'a RistrettoPoint,
            pub A: &'a RistrettoPoint,
            pub X0: &'a RistrettoPoint,
            pub P: &'a RistrettoPoint,
            pub V: &'a RistrettoPoint,
            pub Cm0: &'a RistrettoPoint,
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
            Cm0: RistrettoPoint,
            V: RistrettoPoint,
        }
        struct Randomnesses {
            m0: Scalar,
            z0: Scalar,
            minus_zQ: Scalar,
        }
        #[structural_match]
        struct Responses {
            m0: Scalar,
            z0: Scalar,
            minus_zQ: Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for Responses {
            #[inline]
            fn clone(&self) -> Responses {
                match *self {
                    Responses {
                    m0: ref __self_0_0,
                    z0: ref __self_0_1,
                    minus_zQ: ref __self_0_2 } =>
                    Responses{m0: ::core::clone::Clone::clone(&(*__self_0_0)),
                              z0: ::core::clone::Clone::clone(&(*__self_0_1)),
                              minus_zQ:
                                  ::core::clone::Clone::clone(&(*__self_0_2)),},
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
                    m0: ref __self_0_0,
                    z0: ref __self_0_1,
                    minus_zQ: ref __self_0_2 } => {
                        let mut debug_trait_builder =
                            f.debug_struct("Responses");
                        let _ =
                            debug_trait_builder.field("m0", &&(*__self_0_0));
                        let _ =
                            debug_trait_builder.field("z0", &&(*__self_0_1));
                        let _ =
                            debug_trait_builder.field("minus_zQ",
                                                      &&(*__self_0_2));
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
                    m0: ref __self_1_0,
                    z0: ref __self_1_1,
                    minus_zQ: ref __self_1_2 } =>
                    match *self {
                        Responses {
                        m0: ref __self_0_0,
                        z0: ref __self_0_1,
                        minus_zQ: ref __self_0_2 } =>
                        (*__self_0_0) == (*__self_1_0) &&
                            (*__self_0_1) == (*__self_1_1) &&
                            (*__self_0_2) == (*__self_1_2),
                    },
                }
            }
            #[inline]
            fn ne(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    m0: ref __self_1_0,
                    z0: ref __self_1_1,
                    minus_zQ: ref __self_1_2 } =>
                    match *self {
                        Responses {
                        m0: ref __self_0_0,
                        z0: ref __self_0_1,
                        minus_zQ: ref __self_0_2 } =>
                        (*__self_0_0) != (*__self_1_0) ||
                            (*__self_0_1) != (*__self_1_1) ||
                            (*__self_0_2) != (*__self_1_2),
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
                                                                           1)
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
                                                                            "z0",
                                                                            &self.z0)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "minus_zQ",
                                                                            &self.minus_zQ)
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
                                    _ =>
                                    _serde::export::Err(_serde::de::Error::invalid_value(_serde::de::Unexpected::Unsigned(__value),
                                                                                         &"field index 0 <= i < 3")),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    "m0" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "z0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    "minus_zQ" =>
                                    _serde::export::Ok(__Field::__field2),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8])
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    b"m0" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"z0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    b"minus_zQ" =>
                                    _serde::export::Ok(__Field::__field2),
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
                                                                                                         &"struct Responses with 3 elements"));
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
                                                                                                         &"struct Responses with 3 elements"));
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
                                                                                                         &"struct Responses with 3 elements"));
                                        }
                                    };
                                _serde::export::Ok(Responses{m0: __field0,
                                                             z0: __field1,
                                                             minus_zQ:
                                                                 __field2,})
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
                                                                               _serde::de::Error>::duplicate_field("m0"));
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
                                                                               _serde::de::Error>::duplicate_field("z0"));
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
                                                                               _serde::de::Error>::duplicate_field("minus_zQ"));
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
                                        match _serde::private::de::missing_field("m0")
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
                                        match _serde::private::de::missing_field("z0")
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
                                        match _serde::private::de::missing_field("minus_zQ")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Responses{m0: __field0,
                                                             z0: __field1,
                                                             minus_zQ:
                                                                 __field2,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["m0", "z0", "minus_zQ"];
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
                                        "valid_credential".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("X0".as_bytes(),
                                        publics.X0.compress().as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("V".as_bytes(),
                                        publics.V.compress().as_bytes());
                transcript.commit_bytes("Cm0".as_bytes(),
                                        publics.Cm0.compress().as_bytes());
                let rng_ctor = transcript.fork_transcript();
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("m0".as_bytes(),
                                                  secrets.m0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("z0".as_bytes(),
                                                  secrets.z0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("minus_zQ".as_bytes(),
                                                  secrets.minus_zQ.as_bytes());
                let mut transcript_rng =
                    rng_ctor.reseed_from_rng(&mut thread_rng());
                let rand =
                    Randomnesses{m0: Scalar::random(&mut transcript_rng),
                                 z0: Scalar::random(&mut transcript_rng),
                                 minus_zQ:
                                     Scalar::random(&mut transcript_rng),};
                let commitments =
                    Commitments{Cm0:
                                    RistrettoPoint::multiscalar_mul(&[rand.m0,
                                                                      rand.z0],
                                                                    &[*(publics.P),
                                                                      *(publics.A)]),
                                V:
                                    RistrettoPoint::multiscalar_mul(&[rand.z0,
                                                                      rand.minus_zQ],
                                                                    &[*(publics.X0),
                                                                      *(publics.A)]),};
                transcript.commit_bytes("com Cm0".as_bytes(),
                                        commitments.Cm0.compress().as_bytes());
                transcript.commit_bytes("com V".as_bytes(),
                                        commitments.V.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                let responses =
                    Responses{m0: &(&challenge * secrets.m0) + &rand.m0,
                              z0: &(&challenge * secrets.z0) + &rand.z0,
                              minus_zQ:
                                  &(&challenge * secrets.minus_zQ) +
                                      &rand.minus_zQ,};
                Proof{challenge: challenge, responses: responses,}
            }
            /// Verify the `Proof` using the public parameters `Publics`.
            #[allow(dead_code)]
            pub fn verify(&self, transcript: &mut Transcript,
                          publics: Publics) -> Result<(), ()> {
                let responses = &self.responses;
                let minus_c = -&self.challenge;
                let commitments =
                    Commitments{Cm0:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.m0,
                                                                               responses.z0]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.P),
                                                                               *(publics.A)]).into_iter().chain(iter::once(publics.Cm0))),
                                V:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.z0,
                                                                               responses.minus_zQ]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.X0),
                                                                               *(publics.A)]).into_iter().chain(iter::once(publics.V))),};
                transcript.commit_bytes(b"domain-sep",
                                        "valid_credential".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("X0".as_bytes(),
                                        publics.X0.compress().as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("V".as_bytes(),
                                        publics.V.compress().as_bytes());
                transcript.commit_bytes("Cm0".as_bytes(),
                                        publics.Cm0.compress().as_bytes());
                transcript.commit_bytes("com Cm0".as_bytes(),
                                        commitments.Cm0.compress().as_bytes());
                transcript.commit_bytes("com V".as_bytes(),
                                        commitments.V.compress().as_bytes());
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
    pub mod committed_values_equal {
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
            pub m0: &'a Scalar,
            pub z0: &'a Scalar,
            pub z1: &'a Scalar,
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
                    *self
                }
            }
        }
        #[rustc_copy_clone_marker]
        pub struct Publics<'a> {
            pub B: &'a RistrettoPoint,
            pub A: &'a RistrettoPoint,
            pub P: &'a RistrettoPoint,
            pub Cm0: &'a RistrettoPoint,
            pub Cm1: &'a RistrettoPoint,
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
                    *self
                }
            }
        }
        struct Commitments {
            Cm0: RistrettoPoint,
            Cm1: RistrettoPoint,
        }
        struct Randomnesses {
            m0: Scalar,
            z0: Scalar,
            z1: Scalar,
        }
        #[structural_match]
        struct Responses {
            m0: Scalar,
            z0: Scalar,
            z1: Scalar,
        }
        #[automatically_derived]
        #[allow(unused_qualifications)]
        impl ::core::clone::Clone for Responses {
            #[inline]
            fn clone(&self) -> Responses {
                match *self {
                    Responses {
                    m0: ref __self_0_0, z0: ref __self_0_1, z1: ref __self_0_2
                    } =>
                    Responses{m0: ::core::clone::Clone::clone(&(*__self_0_0)),
                              z0: ::core::clone::Clone::clone(&(*__self_0_1)),
                              z1:
                                  ::core::clone::Clone::clone(&(*__self_0_2)),},
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
                    m0: ref __self_0_0, z0: ref __self_0_1, z1: ref __self_0_2
                    } => {
                        let mut debug_trait_builder =
                            f.debug_struct("Responses");
                        let _ =
                            debug_trait_builder.field("m0", &&(*__self_0_0));
                        let _ =
                            debug_trait_builder.field("z0", &&(*__self_0_1));
                        let _ =
                            debug_trait_builder.field("z1", &&(*__self_0_2));
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
                    m0: ref __self_1_0, z0: ref __self_1_1, z1: ref __self_1_2
                    } =>
                    match *self {
                        Responses {
                        m0: ref __self_0_0,
                        z0: ref __self_0_1,
                        z1: ref __self_0_2 } =>
                        (*__self_0_0) == (*__self_1_0) &&
                            (*__self_0_1) == (*__self_1_1) &&
                            (*__self_0_2) == (*__self_1_2),
                    },
                }
            }
            #[inline]
            fn ne(&self, other: &Responses) -> bool {
                match *other {
                    Responses {
                    m0: ref __self_1_0, z0: ref __self_1_1, z1: ref __self_1_2
                    } =>
                    match *self {
                        Responses {
                        m0: ref __self_0_0,
                        z0: ref __self_0_1,
                        z1: ref __self_0_2 } =>
                        (*__self_0_0) != (*__self_1_0) ||
                            (*__self_0_1) != (*__self_1_1) ||
                            (*__self_0_2) != (*__self_1_2),
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
                                                                           1)
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
                                                                            "z0",
                                                                            &self.z0)
                            {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(&mut __serde_state,
                                                                            "z1",
                                                                            &self.z1)
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
                                    _ =>
                                    _serde::export::Err(_serde::de::Error::invalid_value(_serde::de::Unexpected::Unsigned(__value),
                                                                                         &"field index 0 <= i < 3")),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str)
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    "m0" =>
                                    _serde::export::Ok(__Field::__field0),
                                    "z0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    "z1" =>
                                    _serde::export::Ok(__Field::__field2),
                                    _ => {
                                        _serde::export::Ok(__Field::__ignore)
                                    }
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8])
                             -> _serde::export::Result<Self::Value, __E> where
                             __E: _serde::de::Error {
                                match __value {
                                    b"m0" =>
                                    _serde::export::Ok(__Field::__field0),
                                    b"z0" =>
                                    _serde::export::Ok(__Field::__field1),
                                    b"z1" =>
                                    _serde::export::Ok(__Field::__field2),
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
                                                                                                         &"struct Responses with 3 elements"));
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
                                                                                                         &"struct Responses with 3 elements"));
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
                                                                                                         &"struct Responses with 3 elements"));
                                        }
                                    };
                                _serde::export::Ok(Responses{m0: __field0,
                                                             z0: __field1,
                                                             z1: __field2,})
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
                                                                               _serde::de::Error>::duplicate_field("m0"));
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
                                                                               _serde::de::Error>::duplicate_field("z0"));
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
                                                                               _serde::de::Error>::duplicate_field("z1"));
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
                                        match _serde::private::de::missing_field("m0")
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
                                        match _serde::private::de::missing_field("z0")
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
                                        match _serde::private::de::missing_field("z1")
                                            {
                                            _serde::export::Ok(__val) =>
                                            __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    };
                                _serde::export::Ok(Responses{m0: __field0,
                                                             z0: __field1,
                                                             z1: __field2,})
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["m0", "z0", "z1"];
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
                                        "committed_values_equal".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("Cm0".as_bytes(),
                                        publics.Cm0.compress().as_bytes());
                transcript.commit_bytes("Cm1".as_bytes(),
                                        publics.Cm1.compress().as_bytes());
                let rng_ctor = transcript.fork_transcript();
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("m0".as_bytes(),
                                                  secrets.m0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("z0".as_bytes(),
                                                  secrets.z0.as_bytes());
                let rng_ctor =
                    rng_ctor.commit_witness_bytes("z1".as_bytes(),
                                                  secrets.z1.as_bytes());
                let mut transcript_rng =
                    rng_ctor.reseed_from_rng(&mut thread_rng());
                let rand =
                    Randomnesses{m0: Scalar::random(&mut transcript_rng),
                                 z0: Scalar::random(&mut transcript_rng),
                                 z1: Scalar::random(&mut transcript_rng),};
                let commitments =
                    Commitments{Cm0:
                                    RistrettoPoint::multiscalar_mul(&[rand.m0,
                                                                      rand.z0],
                                                                    &[*(publics.P),
                                                                      *(publics.A)]),
                                Cm1:
                                    RistrettoPoint::multiscalar_mul(&[rand.m0,
                                                                      rand.z1],
                                                                    &[*(publics.A),
                                                                      *(publics.B)]),};
                transcript.commit_bytes("com Cm0".as_bytes(),
                                        commitments.Cm0.compress().as_bytes());
                transcript.commit_bytes("com Cm1".as_bytes(),
                                        commitments.Cm1.compress().as_bytes());
                let challenge =
                    {
                        let mut bytes = [0; 64];
                        transcript.challenge_bytes(b"chal", &mut bytes);
                        Scalar::from_bytes_mod_order_wide(&bytes)
                    };
                let responses =
                    Responses{m0: &(&challenge * secrets.m0) + &rand.m0,
                              z0: &(&challenge * secrets.z0) + &rand.z0,
                              z1: &(&challenge * secrets.z1) + &rand.z1,};
                Proof{challenge: challenge, responses: responses,}
            }
            /// Verify the `Proof` using the public parameters `Publics`.
            #[allow(dead_code)]
            pub fn verify(&self, transcript: &mut Transcript,
                          publics: Publics) -> Result<(), ()> {
                let responses = &self.responses;
                let minus_c = -&self.challenge;
                let commitments =
                    Commitments{Cm0:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.m0,
                                                                               responses.z0]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.P),
                                                                               *(publics.A)]).into_iter().chain(iter::once(publics.Cm0))),
                                Cm1:
                                    RistrettoPoint::vartime_multiscalar_mul((&[responses.m0,
                                                                               responses.z1]).into_iter().chain(iter::once(&(minus_c))),
                                                                            (&[*(publics.A),
                                                                               *(publics.B)]).into_iter().chain(iter::once(publics.Cm1))),};
                transcript.commit_bytes(b"domain-sep",
                                        "committed_values_equal".as_bytes());
                transcript.commit_bytes("B".as_bytes(),
                                        publics.B.compress().as_bytes());
                transcript.commit_bytes("A".as_bytes(),
                                        publics.A.compress().as_bytes());
                transcript.commit_bytes("P".as_bytes(),
                                        publics.P.compress().as_bytes());
                transcript.commit_bytes("Cm0".as_bytes(),
                                        publics.Cm0.compress().as_bytes());
                transcript.commit_bytes("Cm1".as_bytes(),
                                        publics.Cm1.compress().as_bytes());
                transcript.commit_bytes("com Cm0".as_bytes(),
                                        commitments.Cm0.compress().as_bytes());
                transcript.commit_bytes("com Cm1".as_bytes(),
                                        commitments.Cm1.compress().as_bytes());
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
