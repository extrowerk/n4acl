//! The interactive editor.

use crate::ace::{self, *};
use crate::apply::{self, Scope};
use crate::ids::{IdDb, Source};
use crate::model::{self, Ctx, Decision, Severity, Subject};
use crate::sys::{self, MountInfo, ZfsProps};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{DefaultTerminal, Frame};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub struct Target {
    pub path: PathBuf,
    pub is_dir: bool,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub mount: MountInfo,
    pub props: ZfsProps,
}

impl Target {
    pub fn load(path: PathBuf) -> std::io::Result<Self> {
        let md = std::fs::metadata(&path)?;
        let mount = sys::mount_info(&path);
        let props = sys::zfs_props(mount.dataset.as_deref());
        Ok(Target { is_dir: md.is_dir(), uid: md.uid(), gid: md.gid(), mode: md.mode() & 0o7777, path, mount, props })
    }
    fn refresh_meta(&mut self) {
        if let Ok(md) = std::fs::metadata(&self.path) {
            self.uid = md.uid();
            self.gid = md.gid();
            self.mode = md.mode() & 0o7777;
        }
    }
}

// ---------------------------------------------------------------- editor

const TYPES: [AceType; 4] = [AceType::Allow, AceType::Deny, AceType::Audit, AceType::Alarm];
const WHO_LABELS: [&str; 5] = ["owner@", "group@", "everyone@", "user", "group"];
/// grid columns: perms (2 columns of 7) + flags
const PCOL: [[char; 7]; 2] = [['r', 'w', 'x', 'p', 'd', 'D', 's'], ['a', 'A', 'R', 'W', 'c', 'C', 'o']];
const FCOL: [char; 6] = ['f', 'd', 'i', 'n', 'S', 'F'];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Type,
    Who,
    Name,
    Preset,
    Grid(usize, usize),
}

struct Editor {
    index: Option<usize>,
    insert_at: usize,
    kind: usize,
    who: usize,
    name: String,
    mask: u32,
    flags: u16,
    focus: Focus,
    preset: usize,
    comps: Vec<String>,
    comp_i: usize,
    error: Option<String>,
}

impl Editor {
    fn new_ace(insert_at: usize) -> Self {
        Editor {
            index: None,
            insert_at,
            kind: 0,
            who: 3,
            name: String::new(),
            mask: PRESETS[3].mask,
            flags: 0,
            focus: Focus::Name,
            preset: 3,
            comps: vec![],
            comp_i: 0,
            error: None,
        }
    }

    fn from_ace(i: usize, a: &Ace) -> Self {
        let (who, name) = match a.who {
            Who::Owner => (0, String::new()),
            Who::Group => (1, String::new()),
            Who::Everyone => (2, String::new()),
            Who::User(id) => (3, id.to_string()),
            Who::GroupId(id) => (4, id.to_string()),
        };
        Editor {
            index: Some(i),
            insert_at: i,
            kind: TYPES.iter().position(|t| *t == a.kind).unwrap_or(0),
            who,
            name,
            mask: a.mask,
            flags: a.flags,
            focus: Focus::Grid(0, 0),
            preset: 0,
            comps: vec![],
            comp_i: 0,
            error: None,
        }
    }

    fn needs_name(&self) -> bool {
        self.who >= 3
    }

    fn build(&self, ids: &IdDb) -> Result<Ace, String> {
        let who = match self.who {
            0 => Who::Owner,
            1 => Who::Group,
            2 => Who::Everyone,
            3 => Who::User(ace::resolve_user(self.name.trim(), ids)?),
            _ => Who::GroupId(ace::resolve_group(self.name.trim(), ids)?),
        };
        if who.is_ephemeral() {
            return Err("ephemeral (SID) ids are read-only in this version".into());
        }
        Ok(Ace { kind: TYPES[self.kind], who, mask: self.mask, flags: self.flags })
    }

    fn grid_char(c: usize, r: usize) -> Option<char> {
        match c {
            0 | 1 => Some(PCOL[c][r]),
            _ => FCOL.get(r).copied(),
        }
    }

    fn toggle_perm(&mut self, ch: char) {
        if let Some(p) = PERMS.iter().find(|p| p.ch == ch) {
            self.mask ^= p.bit;
        }
    }

    fn toggle_flag(&mut self, ch: char) {
        if let Some(f) = FLAGS.iter().find(|f| f.ch == ch) {
            self.flags ^= f.bit;
        }
    }

    fn move_focus(&mut self, down: bool) {
        use Focus::*;
        let order = |f: Focus| match f {
            Type => 0,
            Who => 1,
            Name => 2,
            Preset => 3,
            Grid(..) => 4,
        };
        self.focus = match (self.focus, down) {
            (Grid(c, r), true) => {
                let max = if c == 2 { 5 } else { 6 };
                if r < max { Grid(c, r + 1) } else { Type }
            }
            (Grid(c, r), false) => {
                if r > 0 { Grid(c, r - 1) } else { Preset }
            }
            (f, true) => match order(f) {
                0 => Who,
                1 if self.needs_name() => Name,
                1 | 2 => Preset,
                _ => Grid(0, 0),
            },
            (f, false) => match order(f) {
                0 => Grid(0, 6),
                1 => Type,
                2 => Who,
                _ if self.needs_name() => Name,
                _ => Who,
            },
        };
    }

    fn complete(&mut self, ids: &IdDb) {
        if self.comps.is_empty() || !self.comps.contains(&self.name) {
            self.comps = if self.who == 3 { ids.complete_users(&self.name) } else { ids.complete_groups(&self.name) };
            self.comp_i = 0;
        } else {
            self.comp_i = (self.comp_i + 1) % self.comps.len();
        }
        if let Some(c) = self.comps.get(self.comp_i) {
            self.name = c.clone();
        }
    }

    /// returns Some(true)=ok, Some(false)=cancel, None=continue
    fn key(&mut self, k: KeyEvent, ids: &IdDb) -> Option<bool> {
        use Focus::*;
        self.error = None;
        let typing = self.focus == Name;
        match k.code {
            KeyCode::Esc => return Some(false),
            KeyCode::Enter => return Some(true),
            KeyCode::Up => self.move_focus(false),
            KeyCode::Down => self.move_focus(true),
            KeyCode::BackTab => self.move_focus(false),
            KeyCode::Tab if typing => self.complete(ids),
            KeyCode::Tab => self.move_focus(true),
            KeyCode::Left | KeyCode::Right => {
                let right = k.code == KeyCode::Right;
                match self.focus {
                    Type => self.kind = (self.kind + if right { 1 } else { 3 }) % 4,
                    Who => {
                        self.who = (self.who + if right { 1 } else { 4 }) % 5;
                        self.comps.clear();
                    }
                    Preset => self.preset = (self.preset + if right { 1 } else { PRESETS.len() - 1 }) % PRESETS.len(),
                    Grid(c, r) => {
                        let nc = if right { (c + 1).min(2) } else { c.saturating_sub(1) };
                        let nr = if nc == 2 { r.min(5) } else { r };
                        self.focus = Grid(nc, nr);
                    }
                    Name => {}
                }
            }
            KeyCode::Backspace if typing => {
                self.name.pop();
                self.comps.clear();
            }
            KeyCode::Char('u') if typing && k.modifiers.contains(KeyModifiers::CONTROL) => self.name.clear(),
            KeyCode::Char(c) if typing => {
                self.name.push(c);
                self.comps.clear();
            }
            KeyCode::Char(' ') => match self.focus {
                Type => self.kind = (self.kind + 1) % 4,
                Who => self.who = (self.who + 1) % 5,
                Preset => self.mask = PRESETS[self.preset].mask,
                Grid(c, r) => match (c, Self::grid_char(c, r)) {
                    (2, Some(f)) => self.toggle_flag(f),
                    (_, Some(p)) => self.toggle_perm(p),
                    _ => {}
                },
                Name => {}
            },
            KeyCode::Char(c @ '1'..='7') => {
                self.preset = (c as u8 - b'1') as usize;
                self.mask = PRESETS[self.preset].mask;
            }
            KeyCode::Char(c) if PERMS.iter().any(|p| p.ch == c) => self.toggle_perm(c),
            _ => {}
        }
        None
    }

    fn hint(&self, is_dir: bool) -> String {
        match self.focus {
            Focus::Type => "allow grants, deny forbids; the first entry mentioning a permission wins.".into(),
            Focus::Who => "owner@/group@/everyone@ follow the file's current owner and group.".into(),
            Focus::Name => "Name, number or #number. A number is stored as-is (zone / lofs users). Tab completes.".into(),
            Focus::Preset => format!("Space applies '{}' (or press 1-7 anywhere).", PRESETS[self.preset].name),
            Focus::Grid(2, r) => {
                let f = FLAGS.iter().find(|f| f.ch == FCOL[r]).unwrap();
                let extra = if !is_dir && r < 4 { " (ignored on files)" } else { "" };
                format!("{}: {}{extra}", f.name, f.hint)
            }
            Focus::Grid(c, r) => {
                let p = PERMS.iter().find(|p| p.ch == PCOL[c][r]).unwrap();
                format!("{} ({}): {}", p.name, p.ch, p.hint)
            }
        }
    }
}

// ---------------------------------------------------------------- other overlays

struct TestView {
    input: String,
    out: Vec<Line<'static>>,
}

struct ApplyView {
    scope: usize,
    dry: bool,
    backup: bool,
    focus: usize,
    diff: Vec<(char, String)>,
    force: bool,
    msg: Option<String>,
}

enum Overlay {
    None,
    Edit(Box<Editor>),
    Test(TestView),
    Apply(ApplyView),
    Pager { title: String, lines: Vec<Line<'static>>, scroll: u16 },
    Context { items: Vec<(String, Source)>, sel: usize },
    ConfirmQuit,
}

pub struct App {
    t: Target,
    ids: IdDb,
    global: Option<IdDb>,
    acl: Vec<Ace>,
    orig: Vec<Ace>,
    undo: Vec<(Vec<Ace>, usize)>,
    redo: Vec<(Vec<Ace>, usize)>,
    sel: usize,
    names: NameMode,
    overlay: Overlay,
    status: Option<(String, bool)>,
    quit: bool,
    want_editor: bool,
    editor_retry: Option<String>,
    table: TableState,
}

fn popup(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

fn type_style(k: AceType) -> Style {
    match k {
        AceType::Allow => Style::new().fg(Color::Green),
        AceType::Deny => Style::new().fg(Color::Red),
        _ => Style::new().fg(Color::Yellow),
    }
}

fn diff(old: &[String], new: &[String]) -> Vec<(char, String)> {
    let (n, m) = (old.len(), new.len());
    let mut l = vec![vec![0u16; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            l[i][j] = if old[i] == new[j] { l[i + 1][j + 1] + 1 } else { l[i + 1][j].max(l[i][j + 1]) };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n || j < m {
        if i < n && j < m && old[i] == new[j] {
            out.push((' ', old[i].clone()));
            i += 1;
            j += 1;
        } else if j < m && (i == n || l[i][j + 1] >= l[i + 1][j]) {
            out.push(('+', new[j].clone()));
            j += 1;
        } else {
            out.push(('-', old[i].clone()));
            i += 1;
        }
    }
    out
}

impl App {
    pub fn new(t: Target, ids: IdDb, acl: Vec<Ace>) -> Self {
        let global = (!ids.is_global()).then(|| IdDb::load(Source::Global));
        let mut table = TableState::default();
        table.select(Some(0));
        App {
            t,
            ids,
            global,
            orig: acl.clone(),
            acl,
            undo: vec![],
            redo: vec![],
            sel: 0,
            names: NameMode::Both,
            overlay: Overlay::None,
            status: None,
            quit: false,
            want_editor: false,
            editor_retry: None,
            table,
        }
    }

    fn modified(&self) -> bool {
        self.acl != self.orig
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            is_dir: self.t.is_dir,
            ids: &self.ids,
            global: self.global.as_ref(),
            aclmode: self.t.props.aclmode.as_deref(),
            aclinherit: self.t.props.aclinherit.as_deref(),
        }
    }

    fn snapshot(&mut self) {
        self.undo.push((self.acl.clone(), self.sel));
        if self.undo.len() > 200 {
            self.undo.remove(0);
        }
        self.redo.clear();
    }

    fn set_status(&mut self, s: impl Into<String>, err: bool) {
        self.status = Some((s.into(), err));
    }

    fn clamp(&mut self) {
        if self.sel >= self.acl.len() {
            self.sel = self.acl.len().saturating_sub(1);
        }
    }

    fn reload(&mut self) {
        match sys::get_acl(&self.t.path) {
            Ok(a) => {
                if a != self.acl {
                    self.snapshot();
                }
                self.acl = a.clone();
                self.orig = a;
                self.t.refresh_meta();
                self.clamp();
                self.set_status("reloaded from disk", false);
            }
            Err(e) => self.set_status(format!("reload failed: {e}"), true),
        }
    }

    // ------------------------------------------------------------ keys

    pub fn key(&mut self, k: KeyEvent) {
        if k.kind != KeyEventKind::Press {
            return;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match std::mem::replace(&mut self.overlay, Overlay::None) {
            Overlay::None => {
                self.status = None;
                self.key_main(k, ctrl);
            }
            Overlay::Edit(mut ed) => match ed.key(k, &self.ids) {
                Some(true) => match ed.build(&self.ids) {
                    Ok(a) => {
                        self.snapshot();
                        match ed.index {
                            Some(i) => self.acl[i] = a,
                            None => {
                                let at = ed.insert_at.min(self.acl.len());
                                self.acl.insert(at, a);
                                self.sel = at;
                            }
                        }
                    }
                    Err(e) => {
                        ed.error = Some(e);
                        self.overlay = Overlay::Edit(ed);
                    }
                },
                Some(false) => {}
                None => self.overlay = Overlay::Edit(ed),
            },
            Overlay::Test(mut tv) => match k.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    tv.out = self.run_test(&tv.input);
                    self.overlay = Overlay::Test(tv);
                }
                KeyCode::Backspace => {
                    tv.input.pop();
                    self.overlay = Overlay::Test(tv);
                }
                KeyCode::Char(c) => {
                    tv.input.push(c);
                    self.overlay = Overlay::Test(tv);
                }
                _ => self.overlay = Overlay::Test(tv),
            },
            Overlay::Apply(mut av) => {
                let nscope = if self.t.is_dir { 3 } else { 1 };
                match k.code {
                    KeyCode::Esc => return,
                    KeyCode::Up => av.focus = av.focus.saturating_sub(1),
                    KeyCode::Down | KeyCode::Tab => av.focus = (av.focus + 1).min(nscope + 1),
                    KeyCode::Char(' ') => {
                        if av.focus < nscope {
                            av.scope = av.focus;
                        } else if av.focus == nscope {
                            av.dry = !av.dry;
                        } else {
                            av.backup = !av.backup;
                        }
                    }
                    KeyCode::Enter => {
                        self.do_apply(av);
                        return;
                    }
                    _ => {}
                }
                self.overlay = Overlay::Apply(av);
            }
            Overlay::Pager { title, lines, mut scroll } => match k.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {}
                KeyCode::Down | KeyCode::Char('j') => {
                    scroll = scroll.saturating_add(1);
                    self.overlay = Overlay::Pager { title, lines, scroll };
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    scroll = scroll.saturating_sub(1);
                    self.overlay = Overlay::Pager { title, lines, scroll };
                }
                KeyCode::PageDown | KeyCode::Char(' ') => {
                    scroll = scroll.saturating_add(10);
                    self.overlay = Overlay::Pager { title, lines, scroll };
                }
                KeyCode::PageUp => {
                    scroll = scroll.saturating_sub(10);
                    self.overlay = Overlay::Pager { title, lines, scroll };
                }
                _ => self.overlay = Overlay::Pager { title, lines, scroll },
            },
            Overlay::Context { items, mut sel } => match k.code {
                KeyCode::Esc => {}
                KeyCode::Up => {
                    sel = sel.saturating_sub(1);
                    self.overlay = Overlay::Context { items, sel };
                }
                KeyCode::Down => {
                    sel = (sel + 1).min(items.len() - 1);
                    self.overlay = Overlay::Context { items, sel };
                }
                KeyCode::Enter => {
                    let src = items[sel].1.clone();
                    self.ids = IdDb::load(src);
                    self.global = (!self.ids.is_global()).then(|| IdDb::load(Source::Global));
                    self.set_status(format!("names now resolved in {}", self.ids.describe()), false);
                }
                _ => self.overlay = Overlay::Context { items, sel },
            },
            Overlay::ConfirmQuit => match k.code {
                KeyCode::Char('y') | KeyCode::Char('q') => self.quit = true,
                KeyCode::Char('w') => self.open_apply(),
                _ => {}
            },
        }
    }

    fn key_main(&mut self, k: KeyEvent, ctrl: bool) {
        let n = self.acl.len();
        let shift = k.modifiers.contains(KeyModifiers::SHIFT);
        match k.code {
            KeyCode::Char('c') if ctrl => self.try_quit(),
            KeyCode::Char('r') if ctrl => {
                if let Some((a, s)) = self.redo.pop() {
                    self.undo.push((std::mem::replace(&mut self.acl, a), self.sel));
                    self.sel = s;
                    self.clamp();
                } else {
                    self.set_status("nothing to redo", false);
                }
            }
            KeyCode::Char('q') => self.try_quit(),
            KeyCode::Up if shift => self.move_ace(false),
            KeyCode::Down if shift => self.move_ace(true),
            KeyCode::Char('K') => self.move_ace(false),
            KeyCode::Char('J') => self.move_ace(true),
            KeyCode::Up | KeyCode::Char('k') => self.sel = self.sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.sel = (self.sel + 1).min(n.saturating_sub(1)),
            KeyCode::Home | KeyCode::Char('g') => self.sel = 0,
            KeyCode::End | KeyCode::Char('G') => self.sel = n.saturating_sub(1),
            KeyCode::Char('a') => self.overlay = Overlay::Edit(Box::new(Editor::new_ace((self.sel + 1).min(n)))),
            KeyCode::Char('A') => self.overlay = Overlay::Edit(Box::new(Editor::new_ace(0))),
            KeyCode::Enter | KeyCode::Char('e') if n > 0 => {
                let a = self.acl[self.sel];
                if a.who.is_ephemeral() {
                    self.set_status("SID-mapped entries are read-only (move/delete still work)", true);
                } else if let AceType::Other(_) = a.kind {
                    self.set_status("unknown ACE type: read-only", true);
                } else {
                    self.overlay = Overlay::Edit(Box::new(Editor::from_ace(self.sel, &a)));
                }
            }
            KeyCode::Char('x') | KeyCode::Delete if n > 0 => {
                if n == 1 {
                    self.set_status("an ACL needs at least one entry", true);
                } else {
                    self.snapshot();
                    let a = self.acl.remove(self.sel);
                    self.clamp();
                    self.set_status(format!("deleted {} (u to undo)", ace_text(&a, &self.ids, false)), false);
                }
            }
            KeyCode::Char('y') if n > 0 => {
                self.snapshot();
                let a = self.acl[self.sel];
                self.acl.insert(self.sel + 1, a);
                self.sel += 1;
            }
            KeyCode::Char('u') => {
                if let Some((a, s)) = self.undo.pop() {
                    self.redo.push((std::mem::replace(&mut self.acl, a), self.sel));
                    self.sel = s;
                    self.clamp();
                } else {
                    self.set_status("nothing to undo", false);
                }
            }
            KeyCode::Char('t') => {
                let input = self.ids.user_name(self.t.uid).unwrap_or_else(|| self.t.uid.to_string());
                let out = self.run_test(&input);
                self.overlay = Overlay::Test(TestView { input, out });
            }
            KeyCode::Char('i') => self.open_inherit(),
            KeyCode::Char('v') => self.want_editor = true,
            KeyCode::Char('N') => self.names = self.names.next(),
            KeyCode::Char('Z') => self.open_context(),
            KeyCode::Char('w') => self.open_apply(),
            KeyCode::Char('r') => self.reload(),
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.overlay = Overlay::Pager { title: " help ".into(), lines: help_lines(), scroll: 0 }
            }
            _ => {}
        }
    }

    fn try_quit(&mut self) {
        if self.modified() {
            self.overlay = Overlay::ConfirmQuit;
        } else {
            self.quit = true;
        }
    }

    fn move_ace(&mut self, down: bool) {
        let n = self.acl.len();
        if n < 2 || (down && self.sel + 1 >= n) || (!down && self.sel == 0) {
            return;
        }
        self.snapshot();
        let to = if down { self.sel + 1 } else { self.sel - 1 };
        self.acl.swap(self.sel, to);
        self.sel = to;
    }

    fn open_context(&mut self) {
        let mut items = vec![("global zone (incl. LDAP/NIS via nsswitch)".to_string(), Source::Global)];
        for z in sys::zones() {
            items.push((format!("zone {}  ({})", z.name, z.root().display()), Source::Zone { name: z.name.clone(), root: z.root() }));
        }
        items.push(("numeric only".into(), Source::Numeric));
        let cur = self.ids.describe();
        let sel = items.iter().position(|(_, s)| IdDb::load(s.clone()).describe() == cur).unwrap_or(0);
        self.overlay = Overlay::Context { items, sel };
    }

    fn open_inherit(&mut self) {
        if !self.t.is_dir {
            self.set_status("inheritance preview is for directories", true);
            return;
        }
        let ai = self.t.props.aclinherit.as_deref();
        let mut lines: Vec<Line<'static>> = vec![
            Line::from(format!("aclinherit={}  (preview is approximate: ZFS also applies the", ai.unwrap_or("? (assumed restricted)"))),
            Line::from("creation mode and aclmode when the child is created)"),
            Line::from(""),
        ];
        for (title, dir) in [("A new FILE created here gets:", false), ("A new SUBDIRECTORY created here gets:", true)] {
            lines.push(Line::from(title).bold());
            let inh = model::inherit(&self.acl, dir, ai);
            if inh.is_empty() {
                lines.push(Line::from("  (nothing inherited — ZFS builds a plain ACL from the mode)").dim());
            }
            for a in inh {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(ace_text(&a, &self.ids, false), type_style(a.kind)),
                ]));
            }
            lines.push(Line::from(""));
        }
        self.overlay = Overlay::Pager { title: " inheritance preview ".into(), lines, scroll: 0 };
    }

    fn open_apply(&mut self) {
        if !self.modified() && !self.t.is_dir {
            self.set_status("no changes to write", false);
            return;
        }
        let old: Vec<String> = self.orig.iter().map(|a| ace_text(a, &self.ids, false)).collect();
        let new: Vec<String> = self.acl.iter().map(|a| ace_text(a, &self.ids, false)).collect();
        self.overlay = Overlay::Apply(ApplyView { scope: 0, dry: false, backup: true, focus: 0, diff: diff(&old, &new), force: false, msg: None });
    }

    fn do_apply(&mut self, mut av: ApplyView) {
        let scope = Scope::ALL[av.scope];
        if scope == Scope::This && !self.modified() {
            av.msg = Some("no changes to write for this item".into());
            self.overlay = Overlay::Apply(av);
            return;
        }
        // detect changes made by someone else since we loaded
        if !av.force && !av.dry {
            match sys::get_acl(&self.t.path) {
                Ok(cur) if cur != self.orig => {
                    av.force = true;
                    av.msg = Some("ACL changed on disk since it was loaded! Enter again to overwrite, Esc then r to reload.".into());
                    self.overlay = Overlay::Apply(av);
                    return;
                }
                Err(e) => {
                    av.msg = Some(format!("cannot re-read ACL: {e}"));
                    self.overlay = Overlay::Apply(av);
                    return;
                }
                _ => {}
            }
        }
        let rep = apply::run(&apply::Job {
            root: &self.t.path,
            acl: &self.acl,
            scope,
            aclinherit: self.t.props.aclinherit.as_deref(),
            dry_run: av.dry,
            backup: av.backup,
        });
        let mut lines: Vec<Line<'static>> = Vec::new();
        let verb = if av.dry { "would change" } else { "changed" };
        lines.push(Line::from(format!("{verb}: {}   unchanged: {}   errors: {}", rep.changed, rep.unchanged, rep.errors.len())).bold());
        if let Some(b) = &rep.backup {
            lines.push(Line::from(format!("backup: {}", b.display())));
            lines.push(Line::from(format!("restore: n4acl --restore {}", b.display())).dim());
        }
        if !rep.samples.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from("examples:"));
            for (p, o, n) in &rep.samples {
                lines.push(Line::from(format!("  {}  ({o} → {n} entries)", p.display())));
            }
        }
        if !rep.errors.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from("errors:").red());
            for (p, e) in rep.errors.iter().take(200) {
                lines.push(Line::from(format!("  {}: {e}", p.display())).red());
            }
        }
        if !av.dry {
            match sys::get_acl(&self.t.path) {
                Ok(a) => {
                    if a != self.acl {
                        lines.push(Line::from(""));
                        lines.push(Line::from("note: ZFS stored a different ACL than requested (normalised by aclmode/aclinherit?)").yellow());
                    }
                    self.acl = a.clone();
                    self.orig = a;
                    self.clamp();
                }
                Err(e) => lines.push(Line::from(format!("re-read failed: {e}")).red()),
            }
            self.t.refresh_meta();
        }
        self.overlay = Overlay::Pager { title: if av.dry { " dry run ".into() } else { " result ".into() }, lines, scroll: 0 };
    }

    fn run_test(&self, input: &str) -> Vec<Line<'static>> {
        let input = input.trim();
        let (u, g) = match input.split_once(':') {
            Some((u, g)) => (u, Some(g)),
            None => (input, None),
        };
        let uid = match ace::resolve_user(u, &self.ids) {
            Ok(x) => x,
            Err(e) => return vec![Line::from(e).red()],
        };
        let gids: Vec<u32> = match g {
            Some(g) => {
                let mut v = Vec::new();
                for x in g.split(',').filter(|s| !s.is_empty()) {
                    match ace::resolve_group(x, &self.ids) {
                        Ok(id) => v.push(id),
                        Err(e) => return vec![Line::from(e).red()],
                    }
                }
                v
            }
            None => self.ids.user_groups(uid),
        };
        let gnames: Vec<String> =
            gids.iter().map(|g| self.ids.group_name(*g).map(|n| format!("{g}({n})")).unwrap_or(g.to_string())).collect();
        let mut out = vec![
            Line::from(format!("uid {uid}{}  groups: {}", self.ids.user_name(uid).map(|n| format!(" ({n})")).unwrap_or_default(), if gnames.is_empty() { "none".into() } else { gnames.join(" ") })),
            Line::from(""),
        ];
        let res = model::evaluate(&self.acl, &Subject { uid, gids }, self.t.uid, self.t.gid);
        for (p, d) in res {
            if p.bit == SYNCHRONIZE || (!self.t.is_dir && p.bit == DELETE_CHILD) {
                continue;
            }
            let label = format!("{:<22}", if self.t.is_dir { p.dir } else { p.file });
            let (mark, why, st) = match d {
                Decision::Allowed(i) => ("✓", format!("allowed by #{} {}", i + 1, who_display(self.acl[i].who, &self.ids, self.names)), Style::new().green()),
                Decision::Denied(i) => ("✗", format!("denied by #{} {}", i + 1, who_display(self.acl[i].who, &self.ids, self.names)), Style::new().red()),
                Decision::OwnerImplicit => ("✓", "owner (implicit, ZFS policy)".into(), Style::new().green()),
                Decision::NoMatch => ("✗", "no matching entry".into(), Style::new().dim()),
            };
            out.push(Line::from(vec![Span::styled(format!(" {mark} "), st), Span::raw(label), Span::styled(why, st)]));
        }
        out.push(Line::from(""));
        out.push(Line::from("Delete is also allowed via D (delete_child) on the parent directory.").dim());
        out.push(Line::from("Privileged users (root, file_dac_* privileges) bypass ACL checks.").dim());
        out
    }

    // ------------------------------------------------------------ $EDITOR

    fn edit_external(&mut self, term: &mut DefaultTerminal) {
        self.want_editor = false;
        let tmp = std::env::temp_dir().join(format!("n4acl-{}.acl", std::process::id()));
        let body = self.editor_retry.take().unwrap_or_else(|| {
            let mut s = format!(
                "# ACL of {}\n# one entry per line, chmod A= syntax. Ids: name, number or #number ({}).\n# perms rwxpdDaARWcCos  flags fdinSFI  type allow|deny|audit|alarm\n",
                self.t.path.display(),
                self.ids.describe()
            );
            for a in &self.acl {
                s.push_str(&ace_text(a, &self.ids, false));
                s.push('\n');
            }
            s
        });
        if let Err(e) = std::fs::write(&tmp, &body) {
            self.set_status(format!("cannot write temp file: {e}"), true);
            return;
        }
        ratatui::restore();
        let ed = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")).unwrap_or_else(|_| "vi".into());
        let status = std::process::Command::new("sh").arg("-c").arg(format!("{ed} \"$1\"")).arg("sh").arg(&tmp).status();
        *term = ratatui::init();
        let text = std::fs::read_to_string(&tmp).unwrap_or_default();
        let _ = std::fs::remove_file(&tmp);
        if !matches!(status, Ok(s) if s.success()) {
            self.set_status("editor exited with an error; nothing changed", true);
            return;
        }
        match ace::parse_acl(&text, &self.ids) {
            Ok(acl) if acl.is_empty() => self.set_status("empty ACL rejected; nothing changed", true),
            Ok(acl) => {
                if acl != self.acl {
                    self.snapshot();
                    self.acl = acl;
                    self.clamp();
                    self.set_status("ACL replaced from editor (u to undo)", false);
                }
            }
            Err(errs) => {
                let mut s: String = errs.iter().map(|(l, e)| format!("# ERROR line {l}: {e}\n")).collect();
                s.push_str(&text.lines().filter(|l| !l.starts_with("# ERROR")).collect::<Vec<_>>().join("\n"));
                s.push('\n');
                self.editor_retry = Some(s);
                self.set_status(format!("{} parse error(s): {} — press v to fix", errs.len(), errs[0].1), true);
            }
        }
    }

    // ------------------------------------------------------------ drawing

    pub fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        let lints = model::lint(&self.acl, &self.ctx());
        let sel_lints: Vec<&model::Lint> = lints.iter().filter(|l| l.ace == Some(self.sel)).collect();
        let other: Vec<&model::Lint> = lints.iter().filter(|l| l.ace != Some(self.sel) && l.sev == Severity::Warn || l.ace.is_none()).collect();
        let explain = if self.acl.is_empty() {
            vec![]
        } else {
            ace::explain(&self.acl[self.sel], self.t.is_dir, &self.ids, self.global.as_ref())
        };
        let exp_h = (explain.len() + sel_lints.len()) as u16 + 2;
        let lint_h = if other.is_empty() { 0 } else { other.len().min(3) as u16 + 2 };
        let [head, body, exp, lnt, foot] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Min(4),
            Constraint::Length(exp_h.min(10)),
            Constraint::Length(lint_h),
            Constraint::Length(1),
        ])
        .areas(area);

        // header
        let p = &self.t;
        let kind = if p.is_dir { "dir" } else { "file" };
        let mut l1 = vec![Span::raw(format!("{}  ", p.path.display())).bold(), Span::raw(format!("[{kind}]"))];
        if self.modified() {
            l1.push(Span::raw("  ● modified").yellow());
        }
        let l2 = match &p.mount.dataset {
            Some(ds) => {
                let mut s = format!(
                    "ds: {ds}   aclmode={}   aclinherit={}",
                    p.props.aclmode.as_deref().unwrap_or("?"),
                    p.props.aclinherit.as_deref().unwrap_or("?")
                );
                if p.props.zoned {
                    s.push_str("   zoned");
                }
                if p.mount.real_path != std::fs::canonicalize(&p.path).unwrap_or_default() {
                    s.push_str(&format!("   via lofs → {}", p.mount.real_path.display()));
                }
                Line::from(s)
            }
            None => Line::from(format!("fs: {} (not ZFS — ACL support may be limited)", if p.mount.fstype.is_empty() { "?" } else { &p.mount.fstype })).yellow(),
        };
        let uname = |id| who_display(Who::User(id), &self.ids, NameMode::Both).trim_start_matches("user:").to_string();
        let gname = |id| who_display(Who::GroupId(id), &self.ids, NameMode::Both).trim_start_matches("group:").to_string();
        let l3 = Line::from(format!(
            "owner: {}   group: {}   mode {:04o}   {} entries   ids: {}",
            uname(p.uid),
            gname(p.gid),
            p.mode,
            self.acl.len(),
            self.ids.short()
        ));
        f.render_widget(
            Paragraph::new(vec![Line::from(l1), l2, l3]).block(Block::bordered().title(" n4acl ").title_style(Style::new().bold())),
            head,
        );

        // table
        let rows: Vec<Row> = self
            .acl
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let warn = lints.iter().any(|l| l.ace == Some(i) && l.sev == Severity::Warn);
                let mut r = Row::new(vec![
                    Cell::from(format!("{}{}", i + 1, if warn { "!" } else { "" })),
                    Cell::from(a.kind.name()).style(type_style(a.kind)),
                    Cell::from(who_display(a.who, &self.ids, self.names)),
                    Cell::from(flags_compact(a.flags)),
                    Cell::from(mask_compact(a.mask)),
                    Cell::from(preset_label(a.mask)),
                ]);
                if a.has(INHERITED) {
                    r = r.style(Style::new().add_modifier(Modifier::DIM));
                }
                r
            })
            .collect();
        self.table.select(Some(self.sel));
        let table = Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Length(5),
                Constraint::Fill(1),
                Constraint::Length(7),
                Constraint::Length(14),
                Constraint::Length(9),
            ],
        )
        .header(Row::new(["#", "type", "principal", "inherit", "perms", "set"]).style(Style::new().bold().underlined()))
        .row_highlight_style(Style::new().reversed())
        .block(Block::bordered());
        f.render_stateful_widget(table, body, &mut self.table);

        // explanation
        let mut et: Vec<Line> = explain.into_iter().map(Line::from).collect();
        if let Some(first) = et.first_mut() {
            *first = first.clone().bold();
        }
        for l in &sel_lints {
            let st = if l.sev == Severity::Warn { Style::new().yellow() } else { Style::new().cyan() };
            et.push(Line::styled(format!("  ⚠ {}", l.msg), st));
        }
        f.render_widget(
            Paragraph::new(et).wrap(Wrap { trim: false }).block(Block::bordered().title(format!(" #{} ", self.sel + 1))),
            exp,
        );
        if lint_h > 0 {
            let mut lt: Vec<Line> = other
                .iter()
                .take(3)
                .map(|l| {
                    let st = if l.sev == Severity::Warn { Style::new().yellow() } else { Style::new().cyan() };
                    Line::styled(format!("⚠ {}", l.msg), st)
                })
                .collect();
            if other.len() > 3 {
                lt.last_mut().unwrap().push_span(Span::raw(format!("   (+{} more)", other.len() - 3)).dim());
            }
            f.render_widget(Paragraph::new(lt).block(Block::bordered().title(" checks ")), lnt);
        }

        // footer / status
        let footer = match &self.status {
            Some((s, true)) => Line::styled(s.clone(), Style::new().red().bold()),
            Some((s, false)) => Line::styled(s.clone(), Style::new().green()),
            None => Line::from(
                "a add  e edit  x del  J/K move  y dup  u undo  t test  i inherit  v $EDITOR  N names  Z ids  w write  ? help  q quit",
            )
            .dim(),
        };
        f.render_widget(Paragraph::new(footer), foot);

        // overlays
        match &self.overlay {
            Overlay::None => {}
            Overlay::Edit(ed) => self.draw_editor(f, ed),
            Overlay::Test(tv) => {
                let r = popup(area, 84, tv.out.len() as u16 + 5);
                let mut lines = vec![
                    Line::from(vec![Span::raw("Who: "), Span::raw(tv.input.clone()).underlined(), Span::raw("▏")]),
                    Line::from("  name | uid | uid:gid,gid…   Enter: evaluate   Esc: close").dim(),
                ];
                lines.extend(tv.out.iter().cloned());
                f.render_widget(Clear, r);
                f.render_widget(Paragraph::new(lines).block(Block::bordered().title(" test access ")), r);
            }
            Overlay::Apply(av) => self.draw_apply(f, av),
            Overlay::Pager { title, lines, scroll } => {
                let r = popup(area, 90, area.height.saturating_sub(2));
                f.render_widget(Clear, r);
                f.render_widget(
                    Paragraph::new(lines.clone())
                        .wrap(Wrap { trim: false })
                        .scroll((*scroll, 0))
                        .block(Block::bordered().title(title.clone()).title_bottom(" ↑↓ PgUp/PgDn scroll · Esc close ")),
                    r,
                );
            }
            Overlay::Context { items, sel } => {
                let r = popup(area, 74, items.len() as u16 + 4);
                let mut lines = vec![Line::from("Resolve user/group names using:").dim()];
                for (i, (label, _)) in items.iter().enumerate() {
                    let s = format!("{} {label}", if i == *sel { "▶" } else { " " });
                    lines.push(if i == *sel { Line::from(s).reversed() } else { Line::from(s) });
                }
                f.render_widget(Clear, r);
                f.render_widget(Paragraph::new(lines).block(Block::bordered().title(" id context ")), r);
            }
            Overlay::ConfirmQuit => {
                let r = popup(area, 52, 5);
                f.render_widget(Clear, r);
                f.render_widget(
                    Paragraph::new(vec![
                        Line::from("Unsaved changes."),
                        Line::from("y/q quit without saving   w write   other: back").dim(),
                    ])
                    .block(Block::bordered().title(" quit? ")),
                    r,
                );
            }
        }
    }

    fn draw_editor(&self, f: &mut Frame, ed: &Editor) {
        let area = f.area();
        let r = popup(area, 86, 22);
        f.render_widget(Clear, r);
        let foc = |x: Focus| ed.focus == x;
        let hl = |on: bool, s: String| if on { Span::raw(s).reversed() } else { Span::raw(s) };
        let radio = |sel: bool| if sel { "(•)" } else { "( )" };
        let mut lines: Vec<Line> = Vec::new();

        let mut l = vec![Span::raw(" Type:   ").bold()];
        for (i, t) in TYPES.iter().enumerate() {
            l.push(hl(foc(Focus::Type) && ed.kind == i, format!("{} {}", radio(ed.kind == i), t.name())));
            l.push(Span::raw("  "));
        }
        lines.push(Line::from(l));

        let mut l = vec![Span::raw(" Who:    ").bold()];
        for (i, w) in WHO_LABELS.iter().enumerate() {
            l.push(hl(foc(Focus::Who) && ed.who == i, format!("{} {w}", radio(ed.who == i))));
            l.push(Span::raw("  "));
        }
        lines.push(Line::from(l));

        if ed.needs_name() {
            let field = format!("{:<20}", ed.name);
            let mut l = vec![
                Span::raw(" Id:     ").bold(),
                if foc(Focus::Name) { Span::raw(field).underlined().reversed() } else { Span::raw(field).underlined() },
                Span::raw("  "),
            ];
            let is_user = ed.who == 3;
            let res = if is_user { ace::resolve_user(ed.name.trim(), &self.ids) } else { ace::resolve_group(ed.name.trim(), &self.ids) };
            match res {
                Ok(id) => {
                    let here = if is_user { self.ids.user_name(id) } else { self.ids.group_name(id) };
                    let mut s = format!("→ {} {id} · {}: {}", if is_user { "uid" } else { "gid" }, self.ids.short(), here.as_deref().unwrap_or("(none)"));
                    if let Some(g) = &self.global {
                        let gn = if is_user { g.user_name(id) } else { g.group_name(id) };
                        s.push_str(&format!(" · global: {}", gn.as_deref().unwrap_or("(none)")));
                    }
                    if id >= EPHEMERAL_MIN {
                        l.push(Span::raw(s).red());
                    } else {
                        l.push(Span::raw(s).green());
                    }
                }
                Err(_) if ed.name.trim().is_empty() => l.push(Span::raw("name, number or #number").dim()),
                Err(_) => l.push(Span::raw("? not found — use the number").red()),
            }
            if ed.comps.len() > 1 {
                l.push(Span::raw(format!("  [{}/{}]", ed.comp_i + 1, ed.comps.len())).dim());
            }
            lines.push(Line::from(l));
        } else {
            lines.push(Line::from(" Id:     (follows the file's current owner/group)").dim());
        }

        let mut l = vec![Span::raw(" Preset: ").bold()];
        for (i, p) in PRESETS.iter().enumerate() {
            let on = ed.mask == p.mask;
            let s = format!("{}[{}]", i + 1, p.name);
            let sp = if foc(Focus::Preset) && ed.preset == i { Span::raw(s).reversed() } else if on { Span::raw(s).bold().cyan() } else { Span::raw(s) };
            l.push(sp);
            l.push(Span::raw(" "));
        }
        lines.push(Line::from(l));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw(format!(" {:<56}", "Permissions (press the letter to toggle)")).bold(),
            Span::raw("Inheritance").bold(),
        ]));
        let is_dir = self.t.is_dir;
        for r in 0..7 {
            let mut l = vec![Span::raw(" ")];
            for c in 0..2 {
                let ch = PCOL[c][r];
                let p = PERMS.iter().find(|p| p.ch == ch).unwrap();
                let on = ed.mask & p.bit != 0;
                let desc = if is_dir { p.dir } else { p.file };
                let s = format!("[{}] {} {:<22}", if on { "x" } else { " " }, ch, desc);
                l.push(hl(foc(Focus::Grid(c, r)), s));
                l.push(Span::raw("  "));
            }
            if r < 6 {
                let ch = FCOL[r];
                let fl = FLAGS.iter().find(|f| f.ch == ch).unwrap();
                let on = ed.flags & fl.bit != 0;
                let s = format!("[{}] {} {}", if on { "x" } else { " " }, ch, fl.name);
                let sp = hl(foc(Focus::Grid(2, r)), s);
                l.push(if !is_dir && r < 4 { sp.dim() } else { sp });
            } else if ed.flags & INHERITED != 0 {
                l.push(Span::raw("    I inherited (kept)").dim());
            }
            lines.push(Line::from(l));
        }
        lines.push(Line::from(""));
        match ed.build(&self.ids) {
            Ok(a) => {
                lines.push(Line::from(vec![Span::raw(" → ").dim(), Span::styled(ace_text(&a, &self.ids, false), type_style(a.kind))]));
                let ex = ace::explain(&a, is_dir, &self.ids, None);
                if let Some(applies) = ex.iter().find(|s| s.trim_start().starts_with("Applies")) {
                    lines.push(Line::from(format!(" {}", applies.trim_start())).dim());
                }
            }
            Err(e) => lines.push(Line::from(format!(" → {e}")).red()),
        }
        lines.push(Line::from(format!(" {}", ed.hint(is_dir))).cyan());
        if let Some(e) = &ed.error {
            lines.push(Line::from(format!(" {e}")).red().bold());
        }
        let title = match ed.index {
            Some(i) => format!(" edit entry #{} ", i + 1),
            None => format!(" new entry at #{} ", ed.insert_at + 1),
        };
        f.render_widget(
            Paragraph::new(lines).block(
                Block::bordered()
                    .title(title)
                    .title_bottom(" ↑↓←→ move · Space toggle · 1-7 preset · Tab next/complete · Enter OK · Esc cancel "),
            ),
            r,
        );
    }

    fn draw_apply(&self, f: &mut Frame, av: &ApplyView) {
        let area = f.area();
        let nscope = if self.t.is_dir { 3 } else { 1 };
        let mut lines: Vec<Line> = Vec::new();
        let changes = av.diff.iter().filter(|(c, _)| *c != ' ').count();
        if changes == 0 {
            lines.push(Line::from(" (no changes on this item)").dim());
        }
        for (c, s) in av.diff.iter().take(14) {
            let st = match c {
                '+' => Style::new().green(),
                '-' => Style::new().red(),
                _ => Style::new().dim(),
            };
            lines.push(Line::styled(format!(" {c} {s}"), st));
        }
        if av.diff.len() > 14 {
            lines.push(Line::from(format!("   … {} more lines", av.diff.len() - 14)).dim());
        }
        lines.push(Line::from(""));
        for (i, s) in Scope::ALL.iter().take(nscope).enumerate() {
            let t = format!(" {} {}", if av.scope == i { "(•)" } else { "( )" }, s.label());
            lines.push(if av.focus == i { Line::from(t).reversed() } else { Line::from(t) });
        }
        let cb = |on: bool| if on { "[x]" } else { "[ ]" };
        let t = format!(" {} dry run (only count what would change)", cb(av.dry));
        lines.push(if av.focus == nscope { Line::from(t).reversed() } else { Line::from(t) });
        let t = format!(" {} backup current ACLs to {}/", cb(av.backup), apply::backup_dir().display());
        lines.push(if av.focus == nscope + 1 { Line::from(t).reversed() } else { Line::from(t) });
        if av.scope > 0 {
            lines.push(Line::from(" recursion never follows symlinks or crosses into other datasets").dim());
        }
        if let Some(m) = &av.msg {
            lines.push(Line::from(format!(" {m}")).yellow().bold());
        }
        let r = popup(area, 92, lines.len() as u16 + 2);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(Text::from(lines))
                .block(Block::bordered().title(" write ACL ").title_bottom(" ↑↓ select · Space choose · Enter apply · Esc cancel ")),
            r,
        );
    }
}

fn help_lines() -> Vec<Line<'static>> {
    let mut v: Vec<Line<'static>> = vec![
        Line::from("KEYS").bold(),
        Line::from("  ↑↓ j k g G     select entry            J K / Shift-↑↓  move entry up/down"),
        Line::from("  a / A          add after / at top      e Enter         edit entry"),
        Line::from("  x Del          delete entry            y               duplicate entry"),
        Line::from("  u / Ctrl-r     undo / redo             r               reload from disk"),
        Line::from("  t              test access for a user  i               inheritance preview (dirs)"),
        Line::from("  v              edit as text in $EDITOR N               cycle id / name display"),
        Line::from("  Z              id context (zone)       w               write (with recursion options)"),
        Line::from("  ?              this help               q               quit"),
        Line::from(""),
        Line::from("HOW ZFS EVALUATES").bold(),
        Line::from("  Entries are checked top to bottom. For each permission bit, the first entry that"),
        Line::from("  matches you and mentions that bit decides it (allow or deny). Order matters: put"),
        Line::from("  specific denies before broad allows. Entries with 'i' are skipped on this item."),
        Line::from(""),
        Line::from("PERMISSIONS  (compact order rwxpdDaARWcCos)").bold(),
    ];
    for p in PERMS.iter() {
        v.push(Line::from(format!("  {}  {:<17} {}", p.ch, p.name, p.hint)));
    }
    v.push(Line::from(""));
    v.push(Line::from("FLAGS  (compact order fdinSFI)").bold());
    for fl in FLAGS.iter() {
        v.push(Line::from(format!("  {}  {:<17} {}", fl.ch, fl.name, fl.hint)));
    }
    v.push(Line::from(""));
    v.push(Line::from("PRESETS").bold());
    for (i, p) in PRESETS.iter().enumerate() {
        v.push(Line::from(format!("  {}  {:<10} {}", i + 1, p.name, mask_compact(p.mask))));
    }
    for l in [
        "",
        "PRINCIPALS AND IDS",
        "  owner@ group@ everyone@ follow the file's owner/group. user:/group: store a",
        "  numeric id. Typing a number (or #number) stores exactly that id without lookup —",
        "  use this for zone users seen through lofs / delegated datasets. Names are resolved",
        "  in the id context shown in the header (Z to change): the global zone, a zone's",
        "  /etc/passwd+group read from its zonepath (works for halted zones), or numeric only.",
        "  Ids >= 2147483648 are idmap ephemeral ids (SIDs); shown read-only in this version.",
        "",
        "ZFS PROPERTIES",
        "  aclinherit  discard: nothing inherited · noallow: only deny entries · restricted",
        "              (default): C and o removed from inherited allow entries · passthrough:",
        "              inherited as-is · passthrough-x: like passthrough, x only if the",
        "              creating mode asks for it.",
        "  aclmode     what chmod does to an ACL. discard: drops custom entries · groupmask:",
        "              masks user/group entries by group bits · passthrough: only the",
        "              owner@/group@/everyone@ entries change · restricted: chmod fails on",
        "              non-trivial ACLs.",
        "",
        "WRITING",
        "  'this item only' writes one ACL. 'same ACL everywhere' copies it to all children",
        "  (files get it without f/d/n/i). 'refresh inherited' keeps each child's own entries",
        "  and recomputes its inherited (I) ones from the parent. Backups can be replayed with",
        "  n4acl --restore FILE.",
    ] {
        v.push(if l.chars().next().is_some_and(|c| c.is_ascii_uppercase()) { Line::from(l).bold() } else { Line::from(l) });
    }
    v
}

pub fn run(mut app: App) -> std::io::Result<()> {
    let mut term = ratatui::init();
    let res = (|| {
        while !app.quit {
            term.draw(|f| app.draw(f))?;
            if let Event::Key(k) = event::read()? {
                app.key(k);
            }
            if app.want_editor {
                app.edit_external(&mut term);
            }
        }
        Ok(())
    })();
    ratatui::restore();
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn snapshot(app: &mut App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| app.draw(f)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut s = String::new();
        for y in 0..h {
            for x in 0..w {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    fn demo() -> App {
        let ids = IdDb::numeric();
        let acl = parse_acl(
            "user:2002:-w-p----------:fd-----:deny
owner@:rwxpdDaARWcCos:fd-----:allow
group:1001:rwxp-DaARWc--s:fd-----:allow
user:60001:r-x---a-R-c--s:fdi----:allow
user:4711:r-----a-R-c--s:fd-----:allow
user:2147483650:r-x---a-R-c--s:fd----I:allow
everyone@:------a-R-c--s:-------:allow",
            &ids,
        )
        .unwrap();
        let t = Target {
            path: "/tank/zones/web01/root/data/www".into(),
            is_dir: true,
            uid: 1001,
            gid: 1001,
            mode: 0o750,
            mount: MountInfo { dataset: Some("tank/zones/web01/data".into()), fstype: "zfs".into(), ..Default::default() },
            props: ZfsProps { aclmode: Some("restricted".into()), aclinherit: Some("passthrough".into()), zoned: false },
        };
        let mut a = App::new(t, ids, acl);
        a.sel = 2;
        a
    }

    #[test]
    fn render_main_and_overlays() {
        let mut a = demo();
        println!("{}", snapshot(&mut a, 100, 30));
        a.key(KeyEvent::from(KeyCode::Char('e')));
        println!("{}", snapshot(&mut a, 100, 30));
        a.key(KeyEvent::from(KeyCode::Esc));
        a.key(KeyEvent::from(KeyCode::Char('t')));
        println!("{}", snapshot(&mut a, 100, 30));
        a.key(KeyEvent::from(KeyCode::Esc));
        a.key(KeyEvent::from(KeyCode::Char('i')));
        println!("{}", snapshot(&mut a, 100, 30));
    }

    #[test]
    fn edit_add_undo() {
        let mut a = demo();
        let n = a.acl.len();
        a.key(KeyEvent::from(KeyCode::Char('a')));
        for c in "777".chars() {
            a.key(KeyEvent::from(KeyCode::Char(c)));
        }
        a.key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(a.acl.len(), n + 1);
        assert_eq!(a.acl[3].who, Who::User(777));
        a.key(KeyEvent::from(KeyCode::Char('K')));
        assert_eq!(a.acl[2].who, Who::User(777));
        a.key(KeyEvent::from(KeyCode::Char('u')));
        a.key(KeyEvent::from(KeyCode::Char('u')));
        assert_eq!(a.acl.len(), n);
        assert!(!a.modified());
    }
}
