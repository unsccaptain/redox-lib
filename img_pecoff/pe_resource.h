#pragma once

#include <assert.h>
#include <cast.h>
#include <string>
#include <vector>
#include <pe_common.h>
#include <Windows.h>

namespace pecoff {
	using namespace std;

	class PECoffAnalysis;

	class PECoffResourceData {
	public:
		PECoffResourceData() = default;

		PECoffResourceData(PECoffAnalysis* analysis, pecoff_rva_t offset_base, PIMAGE_RESOURCE_DATA_ENTRY data);

		uint32_t GetSize() const { return data_->Size; }

		uint32_t GetCodePage() const { return data_->CodePage; }

		pecoff_rva_t GetData() const { return data_rva_; }

	private:
		pecoff_rva_t data_rva_ = 0;
		PIMAGE_RESOURCE_DATA_ENTRY data_ = nullptr;
	};

	class PECoffResourceNode {
	public:
		/**
		 * @brief һ������identifier��������һ��UNICODE���ַ���������һ��ID
		 */
		struct NodeIdentifier {
			pecoff_res_id_t id = 0;
			pecoff_res_name_t name;
			bool is_name;

			NodeIdentifier(pecoff_res_id_t Id)
				:id(Id), is_name(false) {}

			NodeIdentifier(const pecoff_res_name_t& Name)
				:name(Name), is_name(true) {}

			NodeIdentifier(const NodeIdentifier& other)
				:id(other.id), name(other.name), is_name(other.is_name) {
			}

			~NodeIdentifier() {};
		};

		using child_iter = vector<PECoffResourceNode>::const_iterator;

	public:
		/**
		 * @brief �����Ҷ�ڵ㣬�����ӽڵ�����
		 */
		PECoffResourceNode(PECoffAnalysis* analysis, PIMAGE_RESOURCE_DIRECTORY dir, const NodeIdentifier& id);

		/**
		 * @brief ����Ҷ�ڵ㣬����PECoffResourceData����
		 */
		PECoffResourceNode(PECoffAnalysis* analysis, PIMAGE_RESOURCE_DATA_ENTRY data_entry, const NodeIdentifier& id);

		bool IsLeaf() const { return children_.size() == 0; }

		const NodeIdentifier& GetIdentifier() const { return identifier_; }

		child_iter begin() const { 
			assert(!IsLeaf());
			return children_.cbegin();
		}

		child_iter end() const { 
			assert(!IsLeaf()); 
			return children_.cend(); 
		}

		size_t size() const { 
			assert(!IsLeaf()); 
			return children_.size(); 
		}

		const PECoffResourceData& GetResourceData() const {
			assert(IsLeaf());
			return data_;
		}

	private:
		void CreateChild(pecoff_rva_t offset_base, PIMAGE_RESOURCE_DIRECTORY_ENTRY entry, NodeIdentifier& identifier);

	private:
		PECoffAnalysis* analysis_;
		PIMAGE_RESOURCE_DIRECTORY native_dir_ = nullptr;
		PIMAGE_RESOURCE_DATA_ENTRY native_data_ = nullptr;
		NodeIdentifier identifier_;
		PECoffResourceData data_;
		vector<PECoffResourceNode> children_;
	};

	class PECoffResource {
	public:
		PECoffResource(PECoffAnalysis* analysis, PIMAGE_RESOURCE_DIRECTORY root)
			:analysis_(analysis), 
			/** ���ڵ�û��Identity,ȡ����root���� */
			root_(analysis_, root, PECoffResourceNode::NodeIdentifier(L"ROOT")) {
		}

		/**
		 * @brief ������Դ���ĸ���㣬������identifier����Ч��
		 * @return ��������
		 */
		PECoffResourceNode& GetTreeRoot() { return root_; }

	private:
		PECoffAnalysis* analysis_;
		PECoffResourceNode root_;
	};

}