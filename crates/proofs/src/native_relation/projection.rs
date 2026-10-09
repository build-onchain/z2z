use serde::{
    Serialize, Serializer,
    ser::{Impossible, SerializeStruct},
};

use super::NativeRelationError as CustodyError;

/// Upstream Global exposes these through Serialize but has no getters. Collect
/// only scalar fields; never allocate or traverse proprietary metadata.
#[derive(Default)]
pub struct GlobalMarkers {
    pub coin_type: Option<u32>,
    pub tx_modifiable: Option<u8>,
    pub fallback_lock_time: Option<Option<u32>>,
}

impl GlobalMarkers {
    pub fn read(global: &pczt::common::Global) -> Result<Self, CustodyError> {
        match global.serialize(Projection::Global)? {
            Projected::Global(markers)
                if markers.coin_type.is_some() && markers.tx_modifiable.is_some() =>
            {
                Ok(markers)
            }
            _ => Err(CustodyError::GlobalMetadata),
        }
    }
}

impl serde::ser::Error for CustodyError {
    fn custom<T: core::fmt::Display>(_message: T) -> Self {
        Self::GlobalMetadata
    }
}

enum Projection {
    Global,
    Scalar,
}

enum Projected {
    Global(GlobalMarkers),
    Scalar(u32),
    Optional(Option<u32>),
}

struct GlobalFields(GlobalMarkers);

impl SerializeStruct for GlobalFields {
    type Ok = Projected;
    type Error = CustodyError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        if key == "fallback_lock_time" {
            let value = match value.serialize(Projection::Scalar)? {
                Projected::Optional(value) => value,
                _ => return Err(CustodyError::GlobalMetadata),
            };
            if self.0.fallback_lock_time.replace(value).is_some() {
                return Err(CustodyError::GlobalMetadata);
            }
            return Ok(());
        }
        if key != "coin_type" && key != "tx_modifiable" {
            return Ok(());
        }
        let Projected::Scalar(value) = value.serialize(Projection::Scalar)? else {
            return Err(CustodyError::GlobalMetadata);
        };
        let duplicate = if key == "coin_type" {
            self.0.coin_type.replace(value).is_some()
        } else {
            let value = u8::try_from(value).map_err(|_| CustodyError::GlobalMetadata)?;
            self.0.tx_modifiable.replace(value).is_some()
        };
        if duplicate {
            Err(CustodyError::GlobalMetadata)
        } else {
            Ok(())
        }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Projected::Global(self.0))
    }
}

macro_rules! unsupported_scalars {
    ($($method:ident: $ty:ty),* $(,)?) => {
        $(fn $method(self, _value: $ty) -> Result<Self::Ok, Self::Error> {
            Err(CustodyError::GlobalMetadata)
        })*
    };
}

impl Serializer for Projection {
    type Ok = Projected;
    type Error = CustodyError;
    type SerializeSeq = Impossible<Projected, CustodyError>;
    type SerializeTuple = Impossible<Projected, CustodyError>;
    type SerializeTupleStruct = Impossible<Projected, CustodyError>;
    type SerializeTupleVariant = Impossible<Projected, CustodyError>;
    type SerializeMap = Impossible<Projected, CustodyError>;
    type SerializeStruct = GlobalFields;
    type SerializeStructVariant = Impossible<Projected, CustodyError>;

    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        self.serialize_u32(u32::from(value))
    }

    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        match self {
            Self::Scalar => Ok(Projected::Scalar(value)),
            Self::Global => Err(CustodyError::GlobalMetadata),
        }
    }

    fn serialize_struct(
        self,
        name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        match self {
            Self::Global if name == "Global" => Ok(GlobalFields(GlobalMarkers::default())),
            _ => Err(CustodyError::GlobalMetadata),
        }
    }

    unsupported_scalars!(
        serialize_bool: bool, serialize_i8: i8, serialize_i16: i16,
        serialize_i32: i32, serialize_i64: i64, serialize_u16: u16,
        serialize_u64: u64, serialize_f32: f32, serialize_f64: f64,
        serialize_char: char, serialize_str: &str, serialize_bytes: &[u8],
    );

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(Projected::Optional(None))
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        match value.serialize(self)? {
            Projected::Scalar(value) => Ok(Projected::Optional(Some(value))),
            _ => Err(CustodyError::GlobalMetadata),
        }
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(CustodyError::GlobalMetadata)
    }
}
