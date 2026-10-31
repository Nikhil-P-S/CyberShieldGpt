# ============================================================
# CYBERSHIELD GPT
# RAG MODULE
#
# Technology:
#
# Sentence Transformers
# Chroma
# LangChain
#
# PURPOSE:
#
# 1. Load cybersecurity knowledge
# 2. Split documents
# 3. Generate embeddings
# 4. Store embeddings in Chroma
# 5. Retrieve relevant knowledge
#
# ============================================================


import os

from langchain_community.document_loaders import (
    TextLoader
)

from langchain_text_splitters import (
    RecursiveCharacterTextSplitter
)

from langchain_huggingface import (
    HuggingFaceEmbeddings
)

from langchain_chroma import (
    Chroma
)

from config import RAG_DIR


# ============================================================
# CHROMA DATABASE LOCATION
# ============================================================

CHROMA_DIR = os.path.join(
    RAG_DIR,
    "chroma_db"
)


# ============================================================
# EMBEDDING MODEL
# ============================================================

EMBEDDING_MODEL = (
    "sentence-transformers/all-MiniLM-L6-v2"
)

# ============================================================
# INITIALIZE RAG VECTOR DATABASE
# ============================================================

def initialize_rag():
    """
    Load the existing Chroma database when available.
    Otherwise, create it from the cybersecurity knowledge files.
    """

    if os.path.isdir(CHROMA_DIR):
        try:
            return load_vector_database()
        except Exception as error:
            print(
                "[RAG] Existing vector database could not be loaded:",
                error,
            )
            print("[RAG] Creating the vector database again.")

    return create_vector_database()


# ============================================================
# CREATE EMBEDDING MODEL
# ============================================================

def create_embedding_model():

    embeddings = HuggingFaceEmbeddings(

        model_name=EMBEDDING_MODEL

    )

    return embeddings


# ============================================================
# CREATE A SEARCH QUERY FROM AN INCIDENT
# ============================================================

def create_incident_query(incident):
    """
    Convert structured detection results into a natural-language
    query for retrieving relevant cybersecurity knowledge.
    """

    triggered_rules = incident.get("triggered_rules", [])

    return (
        f"Investigate suspicious IP address "
        f"{incident.get('ip_address', 'Unknown')}. "
        f"Severity: {incident.get('severity', 'Unknown')}. "
        f"Security score: {incident.get('security_score', 0)}. "
        f"Triggered rules: {', '.join(triggered_rules)}. "
        f"Failed logins: {incident.get('failed_login_count', 0)}. "
        f"Night logins: {incident.get('night_login_count', 0)}. "
        f"Access denied: {incident.get('access_denied_count', 0)}. "
        f"Unique users: {incident.get('unique_user_count', 0)}. "
        "Find relevant indicators, possible explanations, "
        "investigation steps, and defensive recommendations."
    )


# ============================================================
# RETRIEVE KNOWLEDGE FOR A SECURITY INCIDENT
# ============================================================

def retrieve_incident_knowledge(incident, k=3):
    """
    Retrieve relevant cybersecurity knowledge for one incident.

    Returns:
        query   - the search query
        results - matching Chroma documents
        context - formatted text for the Groq agent
    """

    query = create_incident_query(incident)

    vector_db = initialize_rag()

    results = vector_db.similarity_search(
        query,
        k=k,
    )

    context = format_rag_results(results)

    print(
        f"[RAG] Retrieved {len(results)} documents for "
        f"{incident.get('ip_address', 'Unknown IP')}"
    )

    return {
        "query": query,
        "results": results,
        "context": context,
    }

# ============================================================
# LOAD RAG DOCUMENTS
# ============================================================

def load_rag_documents():

    documents = []


    # --------------------------------------------------------
    # Find TXT files
    # --------------------------------------------------------

    files = [

        file

        for file in os.listdir(RAG_DIR)

        if file.endswith(".txt")

    ]


    # --------------------------------------------------------
    # Load every TXT file
    # --------------------------------------------------------

    for file in files:

        file_path = os.path.join(
            RAG_DIR,
            file
        )


        loader = TextLoader(
            file_path,
            encoding="utf-8"
        )


        loaded_documents = loader.load()


        # ----------------------------------------------------
        # Add filename as metadata
        # ----------------------------------------------------

        for document in loaded_documents:

            document.metadata["source_file"] = file


        documents.extend(
            loaded_documents
        )


    return documents


# ============================================================
# SPLIT DOCUMENTS
# ============================================================

def split_documents(
    documents
):

    splitter = RecursiveCharacterTextSplitter(

        chunk_size=800,

        chunk_overlap=100

    )


    chunks = splitter.split_documents(
        documents
    )


    return chunks


# ============================================================
# CREATE CHROMA VECTOR DATABASE
# ============================================================

def create_vector_database():

    print(
        "\n[RAG] Loading cybersecurity documents..."
    )


    # --------------------------------------------------------
    # Load documents
    # --------------------------------------------------------

    documents = load_rag_documents()


    print(
        f"[RAG] Documents loaded: "
        f"{len(documents)}"
    )


    # --------------------------------------------------------
    # Split documents
    # --------------------------------------------------------

    chunks = split_documents(
        documents
    )


    print(
        f"[RAG] Document chunks created: "
        f"{len(chunks)}"
    )


    # --------------------------------------------------------
    # Create embedding model
    # --------------------------------------------------------

    print(
        "[RAG] Loading Sentence Transformer..."
    )


    embeddings = create_embedding_model()


    # --------------------------------------------------------
    # Create Chroma database
    # --------------------------------------------------------

    vector_db = Chroma.from_documents(

        documents=chunks,

        embedding=embeddings,

        persist_directory=CHROMA_DIR,

        collection_name="cybersecurity_knowledge"

    )


    print(
        "[RAG] Chroma vector database created."
    )


    return vector_db


# ============================================================
# LOAD EXISTING CHROMA DATABASE
# ============================================================

def load_vector_database():

    embeddings = create_embedding_model()


    vector_db = Chroma(

        persist_directory=CHROMA_DIR,

        embedding_function=embeddings,

        collection_name="cybersecurity_knowledge"

    )


    return vector_db


# ============================================================
# SEARCH CYBERSECURITY KNOWLEDGE
# ============================================================

def search_knowledge(

    query,

    k=3

):

    vector_db = load_vector_database()


    results = vector_db.similarity_search(

        query,

        k=k

    )


    return results


# ============================================================
# CONVERT RETRIEVED DOCUMENTS TO TEXT
# ============================================================

def format_rag_results(
    results
):

    if not results:

        return "No relevant cybersecurity knowledge found."


    formatted = []


    for document in results:

        source = document.metadata.get(
            "source_file",
            "Unknown"
        )


        text = document.page_content


        formatted.append(

            f"Source: {source}\n"
            f"{text}"

        )


    return "\n\n".join(
        formatted
    )