import { useState, useCallback, useEffect } from 'react';
import type { Note } from '@/types/extended';
import { createNote, deleteNote } from '@/api/notes';

export interface FindingComment {
  id: string;
  findingId: string;
  author: string;
  text: string;
  mentions: string[];
  timestamp: string;
  parentId?: string;
}

const TEAM_MEMBERS = [
  'Analyst 1',
  'Analyst 2',
  'Reviewer',
  'Team Lead',
  'Admin',
];

function extractMentions(text: string): string[] {
  const mentionRegex = /@([a-zA-Z0-9]+(?:\s[a-zA-Z0-9]+){0,2})/g;
  const mentions: string[] = [];
  let match;
  while ((match = mentionRegex.exec(text)) !== null) {
    const name = match[1];
    const found = TEAM_MEMBERS.find(m => m.toLowerCase().includes(name.toLowerCase()));
    if (found && !mentions.includes(found)) {
      mentions.push(found);
    }
  }
  return mentions;
}

interface FindingCommentsProps {
  findingId: string;
  targetName?: string;
}

export function useFindingComments(findingId: string, targetName?: string) {
  const [comments, setComments] = useState<FindingComment[]>([]);
  const [apiNotes, setApiNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newComment, setNewComment] = useState('');
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  const [replyText, setReplyText] = useState('');

  useEffect(() => {
    if (!targetName) return;
    setLoading(true);
    import('@/api/notes').then(({ getNotes }) =>
      getNotes(targetName)
        .then(res => {
          const filtered = res.notes.filter((n: Note) => n.finding_id === findingId);
          setApiNotes(filtered);
          const mapped: FindingComment[] = filtered.map((n: Note) => ({
            id: n.id,
            findingId: n.finding_id,
            author: n.author || 'Unknown',
            text: n.note,
            mentions: n.tags || [],
            timestamp: n.created_at,
          }));
          setComments(mapped);
        })
        .catch(e => setError(e.message))
        .finally(() => setLoading(false))
    );
  }, [findingId, targetName]);

  const addComment = useCallback(async () => {
    if (!newComment.trim()) return;
    const mentions = extractMentions(newComment);
    if (targetName) {
      setSaving(true);
      try {
        const note = await createNote(targetName, {
          finding_id: findingId,
          note: newComment.trim(),
          tags: mentions,
          author: 'Analyst',
        });
        setComments(prev => [...prev, {
          id: note.id,
          findingId: note.finding_id,
          author: note.author || 'Unknown',
          text: note.note,
          mentions: note.tags || [],
          timestamp: note.created_at,
        }]);
        setApiNotes(prev => [...prev, note]);
        setNewComment('');
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setSaving(false);
      }
    } else {
      const comment: FindingComment = {
        id: `comment-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        findingId,
        author: 'current-user',
        text: newComment.trim(),
        mentions,
        timestamp: new Date().toISOString(),
      };
      setComments(prev => [...prev, comment]);
      setNewComment('');
    }
  }, [newComment, findingId, targetName]);

  const deleteComment = useCallback(async (commentId: string) => {
    if (targetName && apiNotes.some(n => n.id === commentId)) {
      try {
        await deleteNote(targetName, commentId);
        setComments(prev => prev.filter(c => c.id !== commentId));
        setApiNotes(prev => prev.filter(n => n.id !== commentId));
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      }
    } else {
      setComments(prev => prev.filter(c => c.id !== commentId));
    }
  }, [targetName, apiNotes]);

  const rootComments = comments.filter(c => !c.parentId);
  const getReplies = (parentId: string) => comments.filter(c => c.parentId === parentId);

  return {
    comments: rootComments,
    getReplies,
    newComment,
    setNewComment,
    addComment,
    deleteComment,
    replyingTo,
    setReplyingTo,
    replyText,
    setReplyText,
    loading,
    saving,
    error,
    teamMembers: TEAM_MEMBERS,
  };
}

export function FindingComments({ findingId, targetName }: FindingCommentsProps) {
  const {
    comments,
    getReplies,
    newComment,
    setNewComment,
    addComment,
    deleteComment,
    replyingTo,
    setReplyingTo,
    replyText,
    setReplyText,
    loading,
    saving,
    error,
    teamMembers,
  } = useFindingComments(findingId, targetName);

  const renderMentions = (text: string) => {
    const parts = text.split(/(@\w+(?:\s+\w+)*)/g);
    return parts.map((part, i) => {
      if (part.startsWith('@')) {
        const name = part.slice(1);
        const matched = teamMembers.find(m => m.toLowerCase().includes(name.toLowerCase()));
        if (matched) {
          return (
            <span key={i} className="text-[var(--accent)] font-bold">
              {part}
            </span>
          );
        }
      }
      return <span key={i}>{part}</span>;
    });
  };

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleString();
  };

  if (loading) return <div className="finding-comments p-4 text-muted">Loading comments...</div>;

  return (
    <div className="finding-comments">
      {error && <div className="mb-2 text-red-400 text-sm">{error}</div>}
      <h4 className="comments-title">Comments ({comments.length})</h4>

      <div className="comments-list">
        {comments.length === 0 && (
          <p className="text-[var(--muted)] text-sm">No comments yet. Start the discussion.</p>
        )}

        {comments.map(comment => {
          const replies = getReplies(comment.id);
          return (
            <div key={comment.id} className="comment-thread">
              <div className="comment-item">
                <div className="comment-header">
                  <span className="comment-author">{comment.author}</span>
                  <span className="comment-time">{formatTime(comment.timestamp)}</span>
                  {targetName && (
                    <button className="text-red-400 text-xs ml-2 hover:text-red-300"
                      onClick={() => deleteComment(comment.id)} aria-label="Delete comment">Delete</button>
                  )}
                </div>
                <div className="comment-text">{renderMentions(comment.text)}</div>
                {comment.mentions.length > 0 && (
                  <div className="comment-mentions">
                    Mentioned: {comment.mentions.join(', ')}
                  </div>
                )}
                <button
                  className="comment-reply-btn"
                  onClick={() => setReplyingTo(replyingTo === comment.id ? null : comment.id)}
                >
                  Reply
                </button>
              </div>

              {replies.length > 0 && (
                <div className="comment-replies">
                  {replies.map(reply => (
                    <div key={reply.id} className="comment-item comment-reply">
                      <div className="comment-header">
                        <span className="comment-author">{reply.author}</span>
                        <span className="comment-time">{formatTime(reply.timestamp)}</span>
                      </div>
                      <div className="comment-text">{renderMentions(reply.text)}</div>
                    </div>
                  ))}
                </div>
              )}

              {replyingTo === comment.id && (
                <div className="comment-reply-form">
                  <input
                    type="text"
                    className="form-input"
                    placeholder="Write a reply... Use @ to mention"
                    value={replyText}
                    onChange={e => setReplyText(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        addComment();
                      }
                    }}
                  />
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={addComment}
                    disabled={!replyText.trim() || saving}
                  >
                    {saving ? 'Posting...' : 'Reply'}
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="comment-input-area">
        <textarea
          className="form-textarea"
          placeholder="Add a comment... Use @ to mention team members"
          value={newComment}
          onChange={e => setNewComment(e.target.value)}
          rows={2}
        />
        <div className="comment-input-actions">
          <div className="mention-hint">
            Tip: Use @Analyst, @Reviewer, etc. to mention
          </div>
          <button
            className="btn btn-primary"
            onClick={addComment}
            disabled={!newComment.trim() || saving}
          >
            {saving ? 'Posting...' : 'Post Comment'}
          </button>
        </div>
      </div>
    </div>
  );
}
