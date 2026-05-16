import React, { memo } from 'react';
import {
  Home, Target, Shield, Activity, ChevronRight, ChevronDown, Menu, X,
  CheckCircle, AlertCircle, AlertTriangle, XCircle, Play, Square, RefreshCw,
  Settings, Search, Eye, EyeOff, Trash2, Edit, Plus, Minus, ArrowLeft,
  ArrowRight, Filter, Download, Upload, Copy, ExternalLink, Info,
  Clock, Zap, BarChart3, FileText, Terminal, Globe, Lock, Unlock,
  Bug, Cpu, Network, Scan, ShieldCheck, AlertOctagon, TrendingUp,
  TrendingDown, ChevronLeft, ChevronUp, MoreVertical, MoreHorizontal, Moon, Sun, Database,
  MessageSquare, type LucideIcon,
} from 'lucide-react';

export {
  Home, Target, Shield, Activity, ChevronRight, ChevronDown, Menu, X,
  CheckCircle, AlertCircle, AlertTriangle, XCircle, Play, Square, RefreshCw,
  Settings, Search, Eye, EyeOff, Trash2, Edit, Plus, Minus, ArrowLeft,
  ArrowRight, Filter, Download, Upload, Copy, ExternalLink, Info,
  Clock, Zap, BarChart3, FileText, Terminal, Globe, Lock, Unlock,
  Bug, Cpu, Network, Scan, ShieldCheck, AlertOctagon, TrendingUp,
  TrendingDown, ChevronLeft, ChevronUp, MoreVertical, MoreHorizontal, Moon, Sun, Database,
  MessageSquare,
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
]);

export const Icon = memo(function Icon({ name, size = 16, color, className = '', strokeWidth = 2 }: IconProps) {
  const lucideIcon = iconMap.get(name);
  if (!lucideIcon) return null;
  return React.createElement(lucideIcon, { size, color, className, strokeWidth });
});
