import { memo, createElement } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Home, Target, Shield, Activity, ChevronRight, ChevronDown, Menu, X,
  CheckCircle, AlertCircle, AlertTriangle, XCircle, Play, Square, RefreshCw,
  Settings, Search, Eye, EyeOff, Trash2, Edit, Plus, Minus, ArrowLeft,
  ArrowRight, Filter, Download, Upload, Copy, ExternalLink, Info,
  Clock, Zap, BarChart3, FileText, Terminal, Globe, Lock, Unlock,
  Bug, Cpu, Network, Scan, ShieldCheck, AlertOctagon, TrendingUp,
  TrendingDown, ChevronLeft, ChevronUp, MoreVertical, MoreHorizontal, Moon, Sun, Database,
  MessageSquare, LayoutGrid, List, Loader2, Briefcase, LogIn, LockKeyhole,
  ScanLine, Workflow, Bookmark, BookmarkCheck, ShieldAlert, Crown, GitBranch,
  Radio, HardDrive, Gauge, KeyRound, Server, CalendarClock, PanelLeft,
  GitCommitHorizontal, Clock3, CheckCircle2, Fingerprint, MousePointer2,
  Wifi, WifiOff, HelpCircle, ClipboardPaste, RefreshCcw, ArrowLeftRight,
  GitMerge, FileDown, Send, Inbox, Crosshair, GripVertical,
  Package, Library, Sparkles, FileJson, FileCode2, Circle, Check,
} from 'lucide-react';

export {
  Home, Target, Shield, Activity, ChevronRight, ChevronDown, Menu, X,
  CheckCircle, AlertCircle, AlertTriangle, Play, Square, RefreshCw,
  Settings, Search, Eye, EyeOff, Trash2, Edit, Plus, Minus, ArrowLeft,
  ArrowRight, Filter, Download, Upload, Copy, ExternalLink, Info,
  Clock, Zap, BarChart3, FileText, Terminal, Globe, Lock, Unlock,
  Bug, Cpu, Network, Scan, ShieldCheck, AlertOctagon, TrendingUp,
  TrendingDown, ChevronLeft, ChevronUp, MoreVertical, MoreHorizontal, Moon, Sun, Database,
  MessageSquare, LayoutGrid, List, Loader2, Briefcase, LogIn, LockKeyhole,
  ScanLine, Workflow, Bookmark, BookmarkCheck, ShieldAlert, Crown, GitBranch,
  Radio, HardDrive, Gauge, KeyRound, Server, CalendarClock, PanelLeft,
  GitCommitHorizontal, Clock3, CheckCircle2, Fingerprint, MousePointer2,
  Wifi, WifiOff, HelpCircle, ClipboardPaste, RefreshCcw, ArrowLeftRight,
  GitMerge, FileDown, Send, Inbox, Crosshair, GripVertical,
  Package, Library, Sparkles, FileJson, FileCode2, Circle, Check,
};

export type { LucideIcon };

export interface IconProps {
  name: string;
  size?: number;
  color?: string;
  className?: string;
  strokeWidth?: number;
}

const iconMap = new Map<string, LucideIcon>([
  ['home', Home], ['target', Target], ['shield', Shield], ['activity', Activity],
  ['chevronRight', ChevronRight], ['chevronDown', ChevronDown], ['menu', Menu], ['x', X],
  ['checkCircle', CheckCircle], ['alertCircle', AlertCircle], ['alertTriangle', AlertTriangle], ['xCircle', XCircle],
  ['play', Play], ['stop', Square], ['refresh', RefreshCw], ['settings', Settings], ['search', Search],
  ['eye', Eye], ['eyeOff', EyeOff], ['trash', Trash2], ['edit', Edit], ['plus', Plus], ['minus', Minus],
  ['arrowLeft', ArrowLeft], ['arrowRight', ArrowRight], ['filter', Filter], ['download', Download],
  ['upload', Upload], ['copy', Copy], ['externalLink', ExternalLink], ['info', Info],
  ['clock', Clock], ['zap', Zap], ['barChart', BarChart3], ['fileText', FileText], ['terminal', Terminal],
  ['globe', Globe], ['lock', Lock], ['unlock', Unlock], ['bug', Bug], ['cpu', Cpu],
  ['network', Network], ['scan', Scan], ['shieldCheck', ShieldCheck], ['alertOctagon', AlertOctagon],
  ['trendingUp', TrendingUp], ['trendingDown', TrendingDown], ['chevronLeft', ChevronLeft],
  ['chevronUp', ChevronUp], ['moreVertical', MoreVertical], ['moreHorizontal', MoreHorizontal],
  ['moon', Moon], ['sun', Sun], ['database', Database], ['messageSquare', MessageSquare],
  ['layoutGrid', LayoutGrid], ['list', List], ['loader2', Loader2],
  ['briefcase', Briefcase], ['logIn', LogIn], ['lockKeyhole', LockKeyhole],
  ['scanLine', ScanLine], ['workflow', Workflow], ['bookmark', Bookmark],
  ['bookmarkCheck', BookmarkCheck], ['shieldAlert', ShieldAlert], ['crown', Crown],
  ['gitBranch', GitBranch], ['radio', Radio], ['hardDrive', HardDrive],
  ['gauge', Gauge], ['keyRound', KeyRound], ['server', Server],
  ['calendarClock', CalendarClock], ['panelLeft', PanelLeft],
  ['gitCommitHorizontal', GitCommitHorizontal], ['clock3', Clock3],
  ['checkCircle2', CheckCircle2], ['fingerprint', Fingerprint],
  ['mousePointer2', MousePointer2], ['wifi', Wifi], ['wifiOff', WifiOff],
  ['helpCircle', HelpCircle], ['clipboardPaste', ClipboardPaste],
  ['refreshCcw', RefreshCcw], ['arrowLeftRight', ArrowLeftRight],
  ['gitMerge', GitMerge], ['xCircle', XCircle], ['fileDown', FileDown],
  ['send', Send], ['inbox', Inbox], ['crosshair', Crosshair],
  ['gripVertical', GripVertical], ['package', Package], ['library', Library],
  ['sparkles', Sparkles], ['fileJson', FileJson], ['fileCode2', FileCode2],
  ['circle', Circle], ['check', Check],
]);

export const Icon = memo(function Icon({ name, size = 16, color, className = '', strokeWidth = 2 }: IconProps) {
  const lucideIcon = iconMap.get(name);
  if (!lucideIcon) return null;
  return createElement(lucideIcon, { size, color, className, strokeWidth });
});
