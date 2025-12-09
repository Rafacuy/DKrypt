#!/usr/bin/env python3
"""
DKrypt Prompt-Toolkit Completer
This module provides a completer for prompt-toolkit that integrates with the
existing suggestion engine of DKrypt.
"""

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from typing import Iterable, Dict, Any

from core.cli.completer import SmartCompleter


class DKryptCompleter(Completer):
    """
    A prompt-toolkit completer that uses the SmartCompleter and EnhancedSuggester
    to provide context-aware completions.
    """

    def __init__(self, smart_completer: SmartCompleter):
        self.smart_completer = smart_completer

    def get_completions(self, document: Document, complete_event) -> Iterable[Completion]:
        """
        Get completions for the current input.
        This method is called by prompt-toolkit on every keypress.
        """
        word_before_cursor = document.get_word_before_cursor(WORD=True)
        completions = self.smart_completer.get_completions(document)

        for completion_text in completions:
            meta = self._get_completion_meta(document, completion_text)
            yield Completion(
                completion_text,
                start_position=-len(word_before_cursor),
                display_meta=meta
            )

    def _get_completion_meta(self, document: Document, completion_text: str) -> str:
        """
        Get metadata for a completion.
        This metadata is displayed in the completion menu.
        """
        parts = document.text.lstrip().split()
        command = parts[0] if parts else ""

        if command == "use" or command == "info" or command == "help":
            # It's a module
            return self.smart_completer.suggestor.get_module_description(completion_text)
        elif command == "set":
            if self.smart_completer.current_module:
                 option_info = self.smart_completer.suggestor.get_module_option_info(
                    self.smart_completer.current_module,
                    completion_text
                 )
                 if option_info.get('description'):
                     return option_info['description']
        return ""
