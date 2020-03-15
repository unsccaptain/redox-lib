#pragma once

#include <vector>
#include <map>
#include <string>
#include <assert.h>

namespace box {
	using namespace std;

	class BoxData {
	public:
		enum class Kind {
			kUndefined = 0,
			kNull,
			kIntrinsic,
			kCompound,
			kObject,
			kArray,
			kArrayBuffer,
			kUint = 100,
			kInt
		};

		explicit BoxData(Kind kind) :
			kind_(kind), ref_count_(0) {
		}

		Kind GetKind() { return kind_; }

		// 取出的属性相当于成为了右值，在没有被绑定成为左值之前，是不需要加引用计数的
		BoxData* GetProperty(const string& name);

		void SetProperty(const string& name, BoxData* prop);

		uint64_t GetInternal(unsigned index);

		void SetInternal(unsigned index, uint64_t data);

		void Ref();

		void Deref();

		virtual ~BoxData() = 0;

		template<class T>
		T* Cast() {
			if (T::KindOf != this->KindOf)
				throw(exception("Can't cast type safely!"));
			return dynamic_cast<T*>(this);
		}

	public:
		static const Kind KindOf = Kind::kUndefined;

	protected:
		Kind kind_;
		size_t ref_count_;
		map<string, BoxData*> property_;
		uint64_t internal_[4];

	};

	class BoxNull :public BoxData {
	public:
		BoxNull() :
			BoxData(Kind::kNull) {
		}

		static BoxNull* New() {
			return new BoxNull();
		}

	public:
		static const Kind KindOf = Kind::kNull;

	};

	class BoxIntrinsic :public BoxData {
	public:
		enum class Type {
			UINT8,
			UINT16,
			UINT32,
			UINT64,
			INT8,
			INT16,
			INT32,
			INT64,
			Float
		};

		BoxIntrinsic()
			:BoxData(Kind::kIntrinsic) {
		}

		void SetUint8Value(uint8_t value) {
			intrinsic_data_.u8 = value;
			type_ = Type::UINT8;
		}

		void SetUint16Value(uint16_t value) {
			intrinsic_data_.u16 = value;
			type_ = Type::UINT16;
		}

		void SetUint32Value(uint32_t value) {
			intrinsic_data_.u32 = value;
			type_ = Type::UINT32;
		}

		void SetUint64Value(uint64_t value) {
			intrinsic_data_.u64 = value;
			type_ = Type::UINT64;
		}

		void SetInt8Value(int8_t value) {
			intrinsic_data_.i8 = value;
			type_ = Type::INT8;
		}

		void SetInt16Value(int16_t value) {
			intrinsic_data_.i16 = value;
			type_ = Type::INT16;
		}

		void SetInt32Value(int32_t value) {
			intrinsic_data_.i32 = value;
			type_ = Type::INT32;
		}

		void SetInt64Value(int64_t value) {
			intrinsic_data_.i64 = value;
			type_ = Type::INT64;
		}

		Type GetType() {
			return type_;
		}

		template<class T>
		T As() {
			if (is_same<T, uint8_t>::value) {
				return intrinsic_data_.u8;
			}
			if (is_same<T, uint16_t>::value) {
				return intrinsic_data_.u16;
			}
			if (is_same<T, uint32_t>::value) {
				return intrinsic_data_.u32;
			}
			if (is_same<T, uint64_t>::value) {
				return intrinsic_data_.u64;
			}
			if (is_same<T, int8_t>::value) {
				return intrinsic_data_.i8;
			}
			if (is_same<T, int16_t>::value) {
				return intrinsic_data_.i16;
			}
			if (is_same<T, int32_t>::value) {
				return intrinsic_data_.i32;
			}
			if (is_same<T, int64_t>::value) {
				return intrinsic_data_.i64;
			}
			throw(exception("Can't cast intrinsic type!"));
		}

		static BoxIntrinsic* New();

		static BoxIntrinsic* New(uint8_t val);

		static BoxIntrinsic* New(uint16_t val);

		static BoxIntrinsic* New(uint32_t val);

		static BoxIntrinsic* New(unsigned long val);

		static BoxIntrinsic* New(uint64_t val);

		static BoxIntrinsic* New(int8_t val);

		static BoxIntrinsic* New(int16_t val);

		static BoxIntrinsic* New(int32_t val);

		static BoxIntrinsic* New(long val);

		static BoxIntrinsic* New(int64_t val);

	public:
		static const Kind KindOf = Kind::kIntrinsic;

	private:
		virtual ~BoxIntrinsic() {}

	private:
		union {
			uint8_t u8;
			uint16_t u16;
			uint32_t u32;
			uint64_t u64;
			int8_t i8;
			int16_t i16;
			int32_t i32;
			int64_t i64;
		}intrinsic_data_;
		Type type_;

	};

	class BoxCompound :public BoxData {
	public:
		BoxCompound()
			:BoxData(Kind::kCompound) {
		}

		void AddField(const string& name, BoxData* data);

		BoxData* GetField(const string& name);

		BoxData*& operator[](const string& name);

		static BoxCompound* New();

	public:
		static const Kind KindOf = Kind::kCompound;

	private:
		virtual ~BoxCompound();

	private:
		using field_data = pair<string, BoxData*>;

		vector<field_data> fields_;
		map<string, size_t> field_map_;

	};

	class BoxObject :public BoxData {
	private:
		BoxObject()
			:BoxData(Kind::kObject) {
		}

	public:
		static const Kind KindOf = Kind::kObject;

	};

	class BoxArray :public BoxData {
	public:
		BoxArray()
			:BoxData(Kind::kArray) {
		}

		void Push(BoxData* element);

		uint32_t Length();

		~BoxArray();

		static BoxArray* New();

		static BoxArray* New(uint8_t arr, size_t len) {

		}

	public:
		static const Kind KindOf = Kind::kArray;

	private:
		vector<BoxData*> elements_;

	};

	class BoxArrayBuffer :public BoxData {
	public:
		BoxArrayBuffer()
			:BoxData(Kind::kArrayBuffer) {
		}

		void Push(uint8_t value);

		uint32_t Length();

		static BoxArrayBuffer* New();

		static BoxArrayBuffer* New(uint8_t* buf, size_t len);

	public:
		static const Kind KindOf = Kind::kArrayBuffer;

	private:
		vector<uint8_t> buffer_;

	};

}