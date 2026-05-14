import type { Note, NoteListResponse, NoteCreateRequest, NoteUpdateRequest, NoteDeleteResponse } from '@/types/extended';
export type { Note, NoteListResponse, NoteCreateRequest, NoteUpdateRequest, NoteDeleteResponse };
import { apiClient } from './core';
import { apiCache } from './cache';

export async function getNotes(targetName: string, signal?: AbortSignal): Promise<NoteListResponse> {
  const res = await apiClient.get<NoteListResponse>(`/api/notes/${targetName}`, { signal });
  res.data.notes = res.data.notes.map((n: any) => ({ 
    ...n, 
    id: n.id || n.note_id 
  } as Note));
  return res.data;
}

export async function createNote(targetName: string, payload: NoteCreateRequest, signal?: AbortSignal): Promise<Note> {
  const { data } = await apiClient.post<any>(`/api/notes/${targetName}`, payload, { signal });
  const note: Note = { ...data, id: data.id || data.note_id } as Note;
  apiCache.invalidatePrefix(`/api/notes/${targetName}`);
  return note;
}

export async function updateNote(targetName: string, noteId: string, payload: NoteUpdateRequest, signal?: AbortSignal): Promise<Note> {
  const { data } = await apiClient.put<any>(`/api/notes/${targetName}/${noteId}`, payload, { signal });
  const note: Note = { ...data, id: data.id || data.note_id } as Note;
  apiCache.invalidatePrefix(`/api/notes/${targetName}`);
  return note;
}

export async function deleteNote(targetName: string, noteId: string, signal?: AbortSignal): Promise<NoteDeleteResponse> {
  const { data } = await apiClient.delete<NoteDeleteResponse>(`/api/notes/${targetName}/${noteId}`, { signal });
  apiCache.invalidatePrefix(`/api/notes/${targetName}`);
  return data;
}
