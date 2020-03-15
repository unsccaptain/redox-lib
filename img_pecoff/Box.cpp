
#include "Box.h"

namespace box {

	BoxData* BoxData::GetProperty(const string& name) {
		if (property_[name] == nullptr) {
			return BoxNull::New();
		}
		return property_[name];
	}

	void BoxData::SetProperty(const string& name, BoxData* prop) {
		BoxData* data = property_[name];
		if (data != nullptr) {
			data->Deref();
		}

		prop->Ref();
		property_[name] = prop;
	}

	uint64_t BoxData::GetInternal(unsigned index) {
		return internal_[index];
	}

	void BoxData::SetInternal(unsigned index, uint64_t data) {
		internal_[index] = data;
	}

	void BoxData::Ref() {
		ref_count_++;
	}

	void BoxData::Deref() {
		ref_count_--;
		if (ref_count_ == 0) {
			delete this;
		}
	}

	BoxIntrinsic* BoxIntrinsic::New() {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetUint32Value(0);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(uint8_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetUint8Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(uint16_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetUint16Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(uint32_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetUint32Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(unsigned long val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetUint32Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(uint64_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetUint64Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(int8_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetInt8Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(int16_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetInt16Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(int32_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetInt32Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(long val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetInt32Value(val);
		return box;
	}

	BoxIntrinsic* BoxIntrinsic::New(int64_t val) {
		BoxIntrinsic* box = new BoxIntrinsic();
		box->SetInt64Value(val);
		return box;
	}

	void BoxCompound::AddField(const string& name, BoxData* data) {
		if (field_map_[name] != 0)
			throw(exception("Field member exists!"));

		data->Ref();
		fields_.push_back(field_data(name, data));
		field_map_[name] = fields_.size();
	}

	//void BoxCompound::AddField(const string& name, BoxData* data, void* cpp_internal) {
	//	if (field_map_[name] != 0)
	//		throw(exception("Field member exists!"));

	//	data->Ref();
	//	data->SetInternal(cpp_internal);
	//	fields_.push_back(field_data(name, data));
	//	field_map_[name] = fields_.size();
	//}

	BoxData* BoxCompound::GetField(const string& name) {
		size_t index = field_map_[name];
		if (index == 0)
			throw(exception("Field member doesn't exist!"));

		return fields_[index].second;
	}

	BoxData*& BoxCompound::operator[](const string& name) {
		size_t index = field_map_[name];
		if (index == 0)
			throw(exception("Field member doesn't exist!"));

		return fields_[index].second;
	}

	BoxCompound* BoxCompound::New() {
		return new BoxCompound();
	}

	BoxCompound::~BoxCompound() {
		for (auto field : fields_) {
			field.second->Deref();
		}
	}

	void BoxArray::Push(BoxData* element) {
		element->Ref();
		elements_.push_back(element);
	}

	uint32_t BoxArray::Length() {
		return elements_.size();
	}

	BoxArray::~BoxArray() {
		for (BoxData* data : elements_) {
			data->Deref();
		}
	}

	BoxArray* BoxArray::New() {
		return new BoxArray();
	}

	void BoxArrayBuffer::Push(uint8_t value) {
		buffer_.push_back(value);
	}

	uint32_t BoxArrayBuffer::Length() {
		return buffer_.size();
	}

	BoxArrayBuffer* BoxArrayBuffer::New() {
		return new BoxArrayBuffer();
	}

	BoxArrayBuffer* BoxArrayBuffer::New(uint8_t* buf, size_t len) {
		BoxArrayBuffer* array_buffer = new BoxArrayBuffer();
		for (unsigned i = 0;i < len;i++) {
			array_buffer->Push(buf[i]);
		}
		return array_buffer;
	}

}