#!/usr/bin/env python3
"""
DKrypt Enhanced Completion UI
Professional, slim, and visually refined completion menu system
"""

from typing import List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from prompt_toolkit.formatted_text import FormattedText, HTML
from prompt_toolkit.completion import Completion


class CompletionStyle(Enum):
    """Visual styles for completion items"""
    EXACT = "exact"
    PREFIX = "prefix"
    FUZZY = "fuzzy"
    RECENT = "recent"
    FREQUENT = "frequent"
    REQUIRED = "required"
    OPTIONAL = "optional"
    CATEGORY = "category"
    META = "meta"


CATEGORY_ICONS = {
    "scanners": "🎯",
    "enumeration": "🔎",
    "analysis": "📊",
    "discovery": "⚡",
    "tools": "🔧",
    "required": "❗",
    "optional": "⚙️",
    "views": "👁️",
    "management": "🗂️",
    "commands": "▶️",
    "general": "➡️"
}


@dataclass
class StyledCompletion:
    """Completion with visual styling metadata"""
    text: str
    display: str
    meta: str
    score: float
    style: CompletionStyle
    category: str = ""
    icon: str = ""


class CompletionTheme:
    """Theme configuration for completion UI"""
    
    MINIMAL = {
        'exact': 'bold cyan',
        'prefix': 'cyan',
        'fuzzy': 'dim cyan',
        'recent': 'yellow',
        'frequent': 'green',
        'required': 'bold red',
        'optional': 'dim white',
        'meta': 'dim italic',
        'category': 'bold magenta',
        'score_high': '●',
        'score_med': '◐',
        'score_low': '○',
        'icons': CATEGORY_ICONS
    }
    
    PROFESSIONAL = {
        'exact': 'bold #00d7ff',
        'prefix': '#00d7ff',
        'fuzzy': 'dim #00d7ff',
        'recent': '#ffaf00',
        'frequent': '#00ff87',
        'required': 'bold #ff5f5f',
        'optional': '#b2b2b2',
        'meta': 'italic #7a7a7a',
        'category': 'bold #af87ff',
        'score_high': '█',
        'score_med': '▓',
        'score_low': '░',
        'icons': CATEGORY_ICONS
    }
    
    HIGH_CONTRAST = {
        'exact': 'bold white',
        'prefix': 'white',
        'fuzzy': 'dim white',
        'recent': 'bold yellow',
        'frequent': 'bold green',
        'required': 'bold red',
        'optional': 'dim white',
        'meta': 'dim white',
        'category': 'bold magenta',
        'score_high': '■',
        'score_med': '▣',
        'score_low': '□',
        'icons': CATEGORY_ICONS
    }


class CompletionFormatter:
    """Formats completions with professional styling"""
    
    def __init__(self, theme: str = "professional", mode: str = "standard"):
        self.theme_name = theme
        self.mode = mode
        self.theme = self._load_theme(theme)
        
    def _load_theme(self, theme: str) -> dict:
        themes = {
            'minimal': CompletionTheme.MINIMAL,
            'professional': CompletionTheme.PROFESSIONAL,
            'high_contrast': CompletionTheme.HIGH_CONTRAST,
        }
        return themes.get(theme, CompletionTheme.PROFESSIONAL)
    
    def _get_score_indicator(self, score: float) -> str:
        """Visual indicator for match quality"""
        if score >= 0.9:
            return self.theme['score_high']
        elif score >= 0.6:
            return self.theme['score_med']
        else:
            return self.theme['score_low']
    
    def _get_style_color(self, style: CompletionStyle) -> str:
        """Get color for completion style"""
        return self.theme.get(style.value, self.theme['optional'])
    
    def format_completion_text(self, comp: StyledCompletion, 
                              highlight_prefix: str = "") -> FormattedText:
        """Format completion text with styling"""
        color = self._get_style_color(comp.style)
        
        if self.mode == "minimal":
            return FormattedText([(color, comp.text)])
        
        score_icon = self._get_score_indicator(comp.score)
        
        if highlight_prefix and comp.text.lower().startswith(highlight_prefix.lower()):
            prefix_len = len(highlight_prefix)
            return FormattedText([
                ('', f'{score_icon} '),
                ('bold ' + color, comp.text[:prefix_len]),
                (color, comp.text[prefix_len:])
            ])
        
        return FormattedText([
            ('', f'{score_icon} '),
            (color, comp.text)
        ])
    
    def format_display_text(self, comp: StyledCompletion) -> FormattedText:
        """Format display text (shown in menu)"""
        if self.mode == "minimal":
            return FormattedText([(self._get_style_color(comp.style), comp.display)])
        
        parts = []
        
        icon = self.theme['icons'].get(comp.category, "➡️")
        parts.append(('', f'{icon} '))
        
        color = self._get_style_color(comp.style)
        parts.append((color, f'{comp.display:<20}'))
        
        if self.mode == "detailed" and comp.category:
            parts.append(('', '  '))
            parts.append((self.theme['category'], f'[{comp.category}]'))
        
        return FormattedText(parts)
    
    def format_meta_text(self, comp: StyledCompletion) -> FormattedText:
        """Format metadata text"""
        if not comp.meta or self.mode == "minimal":
            return FormattedText([])
        
        meta_color = self.theme['meta']
        
        max_len = 50 if self.mode == "standard" else 70
        meta_text = comp.meta
        if len(meta_text) > max_len:
            meta_text = meta_text[:max_len-3] + '...'
        
        parts = [(meta_color, meta_text)]
        
        if self.mode == "detailed" and comp.score > 0:
            score_pct = int(comp.score * 100)
            score_icon = self._get_score_indicator(comp.score)
            parts.extend([
                ('', '  '),
                (self.theme['optional'], f'({score_icon} {score_pct}%)')
            ])
        
        return FormattedText(parts)
    
    def create_category_separator(self, category: str) -> FormattedText:
        """Create visual separator for categories"""
        if self.mode == "minimal":
            return FormattedText([])
        
        color = self.theme['category']
        separator = '─' * (60 - len(category) - 5)
        
        return FormattedText([
            ('', '\n'),
            (color, f'── {category.upper()} '),
            ('dim', separator),
            ('', '\n')
        ])


class CompletionUIManager:
    """Manages completion UI presentation and grouping"""
    
    def __init__(self, formatter: CompletionFormatter):
        self.formatter = formatter
        
    def categorize_completions(self, completions: List[StyledCompletion]) -> dict:
        """Group completions by category"""
        categories = {}
        for comp in completions:
            cat = comp.category or "general"
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(comp)
        return categories
    
    def sort_completions(self, completions: List[StyledCompletion]) -> List[StyledCompletion]:
        """Sort completions by relevance"""
        priority = {
            CompletionStyle.EXACT: 5,
            CompletionStyle.PREFIX: 4,
            CompletionStyle.RECENT: 3.5,
            CompletionStyle.FREQUENT: 3,
            CompletionStyle.REQUIRED: 4.5,
            CompletionStyle.FUZZY: 2,
            CompletionStyle.OPTIONAL: 1,
        }
        
        return sorted(
            completions,
            key=lambda c: (priority.get(c.style, 0), c.score, c.text),
            reverse=True
        )
    
    def create_prompt_toolkit_completions(
        self, 
        completions: List[StyledCompletion],
        word_before_cursor: str,
        group_by_category: bool = False
    ) -> List[Completion]:
        """Convert styled completions to prompt-toolkit format"""
        
        sorted_comps = self.sort_completions(completions)
        
        if not group_by_category:
            return [
                Completion(
                    text=comp.text,
                    start_position=-len(word_before_cursor),
                    display=self.formatter.format_display_text(comp),
                    display_meta=self.formatter.format_meta_text(comp)
                )
                for comp in sorted_comps
            ]
        
        result = []
        categories = self.categorize_completions(sorted_comps)
        
        sorted_categories = sorted(categories.keys(), key=lambda c: (c == 'required', c == 'optional', c))
        
        for i, cat_name in enumerate(sorted_categories):
            cat_comps = categories[cat_name]
            
            if i > 0:
                result.append(Completion(text="", display=FormattedText([('', '')])))
            
            display_text = f" {self.formatter.theme['icons'].get(cat_name, '➡️')}  [bold]{cat_name.upper()}[/bold]"
            result.append(Completion(
                text="", 
                display=HTML(f"<style bg='{self.formatter.theme['meta']}' fg='white'>{display_text}</style>")
            ))
            
            for comp in cat_comps:
                result.append(Completion(
                    text=comp.text,
                    start_position=-len(word_before_cursor),
                    display=self.formatter.format_display_text(comp),
                    display_meta=self.formatter.format_meta_text(comp)
                ))
        
        return result


# Convenience functions for quick styling
def style_exact_match(text: str, meta: str = "", score: float = 1.0) -> StyledCompletion:
    return StyledCompletion(text, text, meta, score, CompletionStyle.EXACT)

def style_prefix_match(text: str, meta: str = "", score: float = 0.9) -> StyledCompletion:
    return StyledCompletion(text, text, meta, score, CompletionStyle.PREFIX)

def style_fuzzy_match(text: str, meta: str = "", score: float = 0.6) -> StyledCompletion:
    return StyledCompletion(text, text, meta, score, CompletionStyle.FUZZY)

def style_recent(text: str, meta: str = "", score: float = 0.8) -> StyledCompletion:
    comp = StyledCompletion(text, text, meta, score, CompletionStyle.RECENT)
    comp.icon = "⏱"
    return comp

def style_frequent(text: str, meta: str = "", score: float = 0.85) -> StyledCompletion:
    comp = StyledCompletion(text, text, meta, score, CompletionStyle.FREQUENT)
    comp.icon = "★"
    return comp

def style_required_option(text: str, meta: str = "") -> StyledCompletion:
    comp = StyledCompletion(text, text, meta, 1.0, CompletionStyle.REQUIRED)
    comp.icon = "!"
    return comp

def style_optional_option(text: str, meta: str = "") -> StyledCompletion:
    return StyledCompletion(text, text, meta, 0.7, CompletionStyle.OPTIONAL)
