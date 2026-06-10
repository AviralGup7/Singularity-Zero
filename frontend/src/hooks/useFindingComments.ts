import { useState, useCallback, useRef } from 'react';
import type { Note } from '@/types/extended';
import { getNotes, createNote, updateNote, deleteNote } from '@/api/notes';

export function useFindingComments(targetName: string, findingId: string) {
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newComment, setNewComment] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editText, setEditText] = useState('');
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  const [replyText, setReplyText] = useState('');
  const rollbackRef = useRef<{ notes: Note[] }>({ notes: [] });

  const fetchNotes = useCallback(async () => {
    if (!targetName) return;
    setLoading(true);
    try {
      const res = await getNotes(targetName);
      const filtered = findingId ? res.notes.filter((n: Note) => n.finding_id === findingId) : res.notes;
      setNotes(filtered);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [targetName, findingId]);

  const addComment = useCallback(async (author?: string) => {
    if (!newComment.trim() || !targetName) return;
    setSaving(true);
    // Optimistic: add a placeholder immediately
    const tempId = `temp-${Date.now()}`;
    const optimistic: Note = {
      id: tempId,
      finding_id: findingId || 'general',
      note: newComment.trim(),
      tags: [],
      author: author || 'Analyst',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    rollbackRef.current = { notes: [...notes] };
    setNotes(prev => [...prev, optimistic]);
    setNewComment('');
    try {
      const note = await createNote(targetName, {
        finding_id: findingId || 'general',
        note: optimistic.note,
        tags: [],
        author: optimistic.author,
      });
      // Replace temp with real
      setNotes(prev => prev.map(n => n.id === tempId ? note : n));
    } catch (e: unknown) {
      // Rollback optimistic update
      setNotes(rollbackRef.current.notes);
      setError(e instanceof Error ? e.message : String(e));
      setNewComment(optimistic.note);
    } finally {
      setSaving(false);
    }
  }, [newComment, targetName, findingId, notes]);

  const editComment = useCallback(async (noteId: string, text: string) => {
    if (!text.trim() || !targetName) return;
    setSaving(true);
    rollbackRef.current = { notes: [...notes] };
    // Optimistic: update inline
    setNotes(prev => prev.map(n => n.id === noteId ? { ...n, note: text.trim(), updated_at: new Date().toISOString() } : n));
    setEditingId(null);
    setEditText('');
    try {
      const updated = await updateNote(targetName, noteId, { note: text.trim() });
      setNotes(prev => prev.map(n => n.id === noteId ? updated : n));
    } catch (e: unknown) {
      setNotes(rollbackRef.current.notes);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }, [targetName, notes]);

  const deleteComment = useCallback(async (noteId: string) => {
    if (!targetName) return;
    rollbackRef.current = { notes: [...notes] };
    // Optimistic: remove immediately
    setNotes(prev => prev.filter(n => n.id !== noteId));
    try {
      await deleteNote(targetName, noteId);
    } catch (e: unknown) {
      setNotes(rollbackRef.current.notes);
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [targetName, notes]);

  return {
    notes, loading, saving, error,
    newComment, setNewComment,
    addComment, editComment, deleteComment,
    editingId, setEditingId, editText, setEditText,
    replyingTo, setReplyingTo, replyText, setReplyText,
    fetchNotes,
  };
}
