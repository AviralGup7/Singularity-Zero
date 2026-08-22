import type { Note, NoteListResponse, NoteCreateRequest, NoteUpdateRequest, NoteDeleteResponse } from '@/types/extended';
import { apiClient } from './core';
import { apiCache } from './cache';
export type { Note, NoteListResponse, NoteCreateRequest, NoteUpdateRequest, NoteDeleteResponse };

export function normalizeNotes(value: unknown): Note[] {
  if (!Array.isArray(value)) return [];
  return value.map((n) => {
    const rec = (n && typeof n === 'object' ? n : {}) as Record<string, unknown>;
    return { ...rec, id: String(rec.id || rec.note_id || '') } as Note;
  });
}

export async function getNotes(targetName: string, signal?: AbortSignal): Promise<NoteListResponse> {
  const name = String(targetName ?? '').trim();
  const res = await apiClient.get<NoteListResponse>(`/api/notes/${encodeURIComponent(name)}`, { signal });
  return { ...res.data, notes: normalizeNotes(res.data?.notes) };
}

export async function createNote(targetName: string, payload: NoteCreateRequest, signal?: AbortSignal): Promise<Note> {
  const { data } = await apiClient.post<Record<string, unknown>>(`/api/notes/${targetName}`, payload, { signal });
  const note: Note = { ...data, id: String(data.id || data.note_id || '') } as Note;
  apiCache.invalidatePrefix(`/api/notes/${targetName}`);
  return note;
}

export async function updateNote(targetName: string, noteId: string, payload: NoteUpdateRequest, signal?: AbortSignal): Promise<Note> {
  const { data } = await apiClient.put<Record<string, unknown>>(`/api/notes/${targetName}/${noteId}`, payload, { signal });
  const note: Note = { ...data, id: String(data.id || data.note_id || '') } as Note;
  apiCache.invalidatePrefix(`/api/notes/${targetName}`);
  return note;
}

export async function deleteNote(targetName: string, noteId: string, signal?: AbortSignal): Promise<NoteDeleteResponse> {
  const { data } = await apiClient.delete<NoteDeleteResponse>(`/api/notes/${targetName}/${noteId}`, { signal });
  apiCache.invalidatePrefix(`/api/notes/${targetName}`);
  return data;
}
