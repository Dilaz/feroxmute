//! Reusable TUI widgets for the wizard

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

/// Text input widget with cursor and optional masking
pub struct TextInput<'a> {
    value: &'a str,
    cursor_pos: usize,
    placeholder: &'a str,
    masked: bool,
    focused: bool,
    label: &'a str,
}

impl<'a> TextInput<'a> {
    pub fn new(value: &'a str, cursor_pos: usize) -> Self {
        Self {
            value,
            cursor_pos,
            placeholder: "",
            masked: false,
            focused: false,
            label: "",
        }
    }

    pub fn placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = placeholder;
        self
    }

    pub fn masked(mut self, masked: bool) -> Self {
        self.masked = masked;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let display_value = if self.value.is_empty() {
            Span::styled(self.placeholder, Style::default().fg(Color::DarkGray))
        } else if self.masked {
            Span::raw("•".repeat(self.value.chars().count()))
        } else {
            Span::raw(self.value)
        };

        let border_color = if self.focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", self.label));

        let para = Paragraph::new(Line::from(display_value)).block(block);
        frame.render_widget(para, area);

        // Show cursor when focused
        if self.focused && !self.value.is_empty() {
            let char_count = self.value.chars().count();
            // When masked, each char is displayed as one "•" character
            // When unmasked, cursor_pos maps to display chars directly (ASCII assumption for TUI)
            let cursor_x = area.x + 1 + self.cursor_pos.min(char_count) as u16;
            let cursor_y = area.y + 1;
            frame.set_cursor_position((cursor_x, cursor_y));
        } else if self.focused && self.value.is_empty() {
            frame.set_cursor_position((area.x + 1, area.y + 1));
        }
    }
}

/// Selection list widget
pub struct SelectList<'a> {
    items: &'a [&'a str],
    selected: usize,
    focused: bool,
    label: &'a str,
}

impl<'a> SelectList<'a> {
    pub fn new(items: &'a [&'a str], selected: usize) -> Self {
        Self {
            items,
            selected,
            focused: false,
            label: "",
        }
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let border_color = if self.focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", self.label));

        let lines: Vec<Line> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let prefix = if i == self.selected { "› " } else { "  " };
                let style = if i == self.selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(format!("{}{}", prefix, item), style))
            })
            .collect();

        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, area);
    }
}

/// Checkbox group widget
pub struct CheckboxGroup<'a> {
    items: &'a [(&'a str, bool)],
    selected: usize,
    focused: bool,
    label: &'a str,
}

impl<'a> CheckboxGroup<'a> {
    pub fn new(items: &'a [(&'a str, bool)], selected: usize) -> Self {
        Self {
            items,
            selected,
            focused: false,
            label: "",
        }
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let border_color = if self.focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", self.label));

        let lines: Vec<Line> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, (label, checked))| {
                let checkbox = if *checked { "[x]" } else { "[ ]" };
                let prefix = if i == self.selected { "› " } else { "  " };
                let style = if i == self.selected {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(
                    format!("{}{} {}", prefix, checkbox, label),
                    style,
                ))
            })
            .collect();

        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, area);
    }
}
