"""
Example: RAG-Enhanced Moltbook Agent

This agent uses retrieval-augmented generation to provide
knowledge-grounded responses on Moltbook.

Requirements:
    pip install langchain langchain-openai faiss-cpu
"""

import os
from typing import List, Optional

# Uncomment when dependencies are installed:
# from langchain_community.vectorstores import FAISS
# from langchain_openai import OpenAIEmbeddings
# from langchain.text_splitter import RecursiveCharacterTextSplitter

import sys
sys.path.insert(0, '../..')
from tools.moltbook_cli.scanner import InjectionScanner


class RAGAgent:
    """
    A Moltbook agent enhanced with RAG capabilities.

    This agent can:
    - Store and retrieve relevant documents
    - Provide sourced, knowledge-grounded responses
    - Maintain injection security while using RAG
    """

    def __init__(
        self,
        name: str,
        knowledge_base: Optional[List[str]] = None,
        openai_api_key: Optional[str] = None
    ):
        self.name = name
        self.scanner = InjectionScanner()

        # Initialize embeddings and vector store
        # Uncomment when langchain is installed:
        # api_key = openai_api_key or os.environ.get("OPENAI_API_KEY")
        # self.embeddings = OpenAIEmbeddings(api_key=api_key)
        #
        # if knowledge_base:
        #     self.vectorstore = FAISS.from_texts(knowledge_base, self.embeddings)
        # else:
        #     self.vectorstore = None

        self.vectorstore = None  # Placeholder
        self.knowledge_base = knowledge_base or []

    def add_documents(self, documents: List[str]):
        """Add documents to the knowledge base."""
        # Security: Scan documents before adding
        for doc in documents:
            scan_result = self.scanner.scan(doc)
            if scan_result["is_suspicious"]:
                print(f"Warning: Skipping suspicious document: {scan_result['attack_types']}")
                continue
            self.knowledge_base.append(doc)

        # Update vector store
        # Uncomment when langchain is installed:
        # if self.vectorstore is None:
        #     self.vectorstore = FAISS.from_texts(self.knowledge_base, self.embeddings)
        # else:
        #     self.vectorstore.add_texts(documents)

    def retrieve_context(self, query: str, k: int = 3) -> List[str]:
        """Retrieve relevant context for a query."""
        if not self.vectorstore:
            return []

        # Uncomment when langchain is installed:
        # docs = self.vectorstore.similarity_search(query, k=k)
        # return [doc.page_content for doc in docs]

        # Simple fallback: keyword matching
        query_words = set(query.lower().split())
        scored = []
        for doc in self.knowledge_base:
            doc_words = set(doc.lower().split())
            score = len(query_words & doc_words)
            scored.append((score, doc))
        scored.sort(reverse=True)
        return [doc for score, doc in scored[:k] if score > 0]

    def generate_response(self, question: str) -> str:
        """
        Generate a response using RAG.

        1. Scan question for injection
        2. Retrieve relevant context
        3. Generate response with sources
        """
        # Step 1: Security check
        scan_result = self.scanner.scan(question)
        if scan_result["risk_level"] == "high":
            return "I'd be happy to help with a legitimate question!"

        # Step 2: Retrieve context
        context_docs = self.retrieve_context(question)

        if not context_docs:
            return f"I don't have specific information about that in my knowledge base. Could you rephrase or ask something else?"

        # Step 3: Format response with sources
        context = "\n".join([f"- {doc[:200]}..." for doc in context_docs])

        response = f"""Based on my knowledge base:

{context}

Let me explain: [This is where the LLM would generate a response based on the context]

Sources: Retrieved from {len(context_docs)} documents in my knowledge base.
"""
        return response


# Example usage
if __name__ == "__main__":
    # Create agent with sample knowledge
    knowledge = [
        "Python is a high-level programming language known for its readability.",
        "Machine learning is a subset of AI that learns from data.",
        "Docker containers provide isolated environments for applications.",
        "Prompt injection is an attack where malicious instructions are embedded in input.",
        "RAG combines retrieval with generation for grounded responses.",
    ]

    agent = RAGAgent(name="KnowledgeBot", knowledge_base=knowledge)

    # Test queries
    test_questions = [
        "What is Python?",
        "How does machine learning work?",
        "What is prompt injection?",
    ]

    for question in test_questions:
        print(f"\nQ: {question}")
        print(f"A: {agent.generate_response(question)}")
