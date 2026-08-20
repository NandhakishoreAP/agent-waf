import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.agent.providers import GroqProvider, TestLLMProvider, OpenAIProvider
from app.api.agent import get_llm_provider
from app.config import settings

@pytest.mark.asyncio
async def test_groq_provider_initialization():
    provider = GroqProvider(api_key="test-key", model="test-model", base_url="https://test.groq.com/v1")
    assert provider.api_key == "test-key"
    assert provider.model == "test-model"
    assert provider.base_url == "https://test.groq.com/v1"
    assert provider.client is not None

@pytest.mark.asyncio
async def test_groq_provider_missing_api_key():
    with patch.object(settings, "GROQ_API_KEY", None):
        provider = GroqProvider(api_key=None)
        with pytest.raises(ValueError, match="Groq API key is missing"):
            await provider.generate(messages=[], tools=[])

def test_get_llm_provider_groq():
    with patch.object(settings, "LLM_PROVIDER", "groq"):
        provider = get_llm_provider()
        assert isinstance(provider, GroqProvider)

def test_get_llm_provider_test():
    with patch.object(settings, "LLM_PROVIDER", "test"):
        provider = get_llm_provider()
        assert isinstance(provider, TestLLMProvider)

def test_get_llm_provider_openai():
    with patch.object(settings, "LLM_PROVIDER", "openai"):
        provider = get_llm_provider()
        assert isinstance(provider, OpenAIProvider)

def test_get_llm_provider_unsupported():
    with patch.object(settings, "LLM_PROVIDER", "unsupported_provider_xyz"):
        with pytest.raises(ValueError, match="Unsupported LLM provider"):
            get_llm_provider()

@pytest.mark.asyncio
async def test_groq_tool_call_response_parsing():
    provider = GroqProvider(api_key="mock_key")
    
    mock_tool_call = MagicMock()
    mock_tool_call.id = "call_abc123"
    mock_tool_call.function.name = "crm.read"
    mock_tool_call.function.arguments = '{"customer_id": "CUST-1001"}'

    mock_message = MagicMock()
    mock_message.tool_calls = [mock_tool_call]
    mock_message.content = None

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
    provider.client = mock_client

    res = await provider.generate(
        messages=[{"role": "user", "content": "Fetch customer CUST-1001"}],
        tools=[{"name": "crm.read", "description": "Read CRM", "parameters": {}}]
    )

    assert res["type"] == "tool_calls"
    assert len(res["tool_calls"]) == 1
    assert res["tool_calls"][0]["id"] == "call_abc123"
    assert res["tool_calls"][0]["name"] == "crm.read"
    assert res["tool_calls"][0]["arguments"] == {"customer_id": "CUST-1001"}
    mock_client.chat.completions.create.assert_called_once()

@pytest.mark.asyncio
async def test_groq_text_response_parsing():
    provider = GroqProvider(api_key="mock_key")

    mock_message = MagicMock()
    mock_message.tool_calls = None
    mock_message.content = "Here is the response."

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
    provider.client = mock_client

    res = await provider.generate(
        messages=[{"role": "user", "content": "Hello"}],
        tools=[]
    )

    assert res["type"] == "text"
    assert res["content"] == "Here is the response."

@pytest.mark.asyncio
async def test_groq_empty_or_invalid_response():
    provider = GroqProvider(api_key="mock_key")

    # Case 1: Empty choices
    mock_response_empty = MagicMock()
    mock_response_empty.choices = []

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response_empty)
    provider.client = mock_client

    with pytest.raises(ValueError, match="Invalid or empty response"):
        await provider.generate(messages=[{"role": "user", "content": "Hello"}], tools=[])

    # Case 2: Content and tool_calls both None
    mock_message = MagicMock()
    mock_message.tool_calls = None
    mock_message.content = None

    mock_choice = MagicMock()
    mock_choice.message = mock_message
    mock_response_none = MagicMock()
    mock_response_none.choices = [mock_choice]

    provider.client.chat.completions.create = AsyncMock(return_value=mock_response_none)
    with pytest.raises(ValueError, match="neither content nor tool_calls"):
        await provider.generate(messages=[{"role": "user", "content": "Hello"}], tools=[])
