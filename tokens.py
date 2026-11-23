"""
Simple text tokenizer using OpenAI's tiktoken library.

tiktoken is a fast BPE (Byte Pair Encoding) tokenizer used by
OpenAI models (GPT-3.5, GPT-4, etc.). It converts text into
token IDs and back.
"""

import tiktoken


class Tokenizer:
    """A wrapper around tiktoken for easy text tokenization."""

    def __init__(self, encoding_name: str = "cl100k_base"):
        """
        Initialize the tokenizer.

        Args:
            encoding_name: The tiktoken encoding to use.
                - "cl100k_base"  -> used by GPT-3.5-turbo, GPT-4
                - "o200k_base"   -> used by GPT-4o
                - "p50k_base"    -> used by older GPT-3 models (e.g. text-davinci-003)
                - "r50k_base"    -> used by GPT-2 / GPT-3 (original)
        """
        self.encoding_name = encoding_name
        self.encoding = tiktoken.get_encoding(encoding_name)

    @classmethod
    def for_model(cls, model_name: str):
        """
        Create a Tokenizer matched to a specific model name,
        e.g. Tokenizer.for_model("gpt-4o")
        """
        encoding = tiktoken.encoding_for_model(model_name)
        instance = cls.__new__(cls)
        instance.encoding_name = encoding.name
        instance.encoding = encoding
        return instance

    def encode(self, text: str) -> list[int]:
        """Convert text into a list of token IDs."""
        return self.encoding.encode(text)

    def decode(self, tokens: list[int]) -> str:
        """Convert a list of token IDs back into text."""
        return self.encoding.decode(tokens)

    def tokenize_to_strings(self, text: str) -> list[str]:
        """
        Convert text into the list of token *strings* (not IDs),
        useful for visualizing how text gets split up.
        """
        token_ids = self.encode(text)
        return [self.encoding.decode([tid]) for tid in token_ids]

    def count_tokens(self, text: str) -> int:
        """Return the number of tokens in a piece of text."""
        return len(self.encode(text))


def demo():
    text = "Hello, world! This is a tokenizer test using tiktoken."

    tokenizer = Tokenizer("cl100k_base")

    print(f"Original text:\n  {text}\n")

    token_ids = tokenizer.encode(text)
    print(f"Token IDs ({len(token_ids)} tokens):\n  {token_ids}\n")

    token_strings = tokenizer.tokenize_to_strings(text)
    print(f"Token strings:\n  {token_strings}\n")

    decoded_text = tokenizer.decode(token_ids)
    print(f"Decoded text (should match original):\n  {decoded_text}\n")

    print(f"Token count: {tokenizer.count_tokens(text)}")


if __name__ == "__main__":
    demo()