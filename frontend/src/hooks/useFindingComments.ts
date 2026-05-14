import { useState, useCallback } from 'react';
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
    try {
      const note = await createNote(targetName, {
        finding_id: findingId || 'general',
        note: newComment.trim(),
        tags: [],
        author: author || 'Analyst',
      });
      setNotes(prev => [...prev, note]);
      setNewComment('');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }, [newComment, targetName, findingId]);

  const editComment = useCallback(async (noteId: string, text: string) => {
    if (!text.trim() || !targetName) return;
    setSaving(true);
    try {
      const updated = await updateNote(targetName, noteId, { note: text.trim() });
      setNotes(prev => prev.map(n => n.id === noteId ? updated : n));
      setEditingId(null);
      setEditText('');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }, [targetName]);

  const deleteComment = useCallback(async (noteId: string) => {
    if (!targetName) return;
    try {
      await deleteNote(targetName, noteId);
      setNotes(prev => prev.filter(n => n.id !== noteId));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [targetName]);

  return {
    notes, loading, saving, error,
    newComment, setNewComment,
    addComment, editComment, deleteComment,
    editingId, setEditingId, editText, setEditText,
    replyingTo, setReplyingTo, replyText, setReplyText,
    fetchNotes,
  };
}
