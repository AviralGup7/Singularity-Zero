import { useState, useCallback, useEffect } from 'react';
import type { Note } from '@/types/extended';
import { useTriageCollaboration } from '@/hooks/useTriageCollaboration';
import { AnalystPresenceIndicator } from '@/components/AnalystPresenceIndicator';

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

function findMentionRanges(text: string, members: string[]): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  const lower = text.toLowerCase();
  for (const member of members) {
    const needle = `@${member.toLowerCase()}`;
    let idx = lower.indexOf(needle);
    while (idx >= 0) {
      ranges.push({ start: idx, end: idx + needle.length });
      idx = lower.indexOf(needle, idx + needle.length);
    }
  }
  return ranges.sort((a, b) => a.start - b.start);
}

function extractMentions(text: string): string[] {
   
  const mentions: string[] = [];
  const ranges = findMentionRanges(text, TEAM_MEMBERS);
  for (const range of ranges) {
    const raw = text.slice(range.start + 1, range.end);
    const found = TEAM_MEMBERS.find(m => m.toLowerCase() === raw.toLowerCase());
    if (found && !mentions.includes(found)) {
      mentions.push(found);
    }
  }
  return mentions;
}

interface FindingCommentsProps {
  findingId: string;
  targetName?: string;
  runId?: string;
}

function useFindingComments(findingId: string, targetName?: string, runId?: string) {
   
  const [comments, setComments] = useState<FindingComment[]>([]);
   
  const [, setApiNotes] = useState<Note[]>([]);
   
  const [loading, setLoading] = useState(false);
   
  const [saving] = useState(false);
   
  const [error, setError] = useState<string | null>(null);
   
  const [newComment, setNewComment] = useState('');
   
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
   
  const [replyText, setReplyText] = useState('');
  const triageRunId = runId || targetName || 'global';
  const collaboration = useTriageCollaboration(triageRunId, findingId);

  useEffect(() => {
    if (collaboration.state) {
      setComments(collaboration.state.comments.map(comment => ({
        id: comment.id,
        findingId: comment.finding_id,
        author: comment.author,
        text: comment.text,
        mentions: comment.mentions || [],
        timestamp: comment.timestamp,
      })));
      return;
    }
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
   
  }, [collaboration.state, findingId, targetName]);

  const addComment = useCallback(async () => {
    if (!newComment.trim()) return;
    const mentions = extractMentions(newComment);
    const text = newComment.trim();
    await collaboration.sendAction('comment_added', {
      comment_id: `comment-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      text,
      mentions,
    });
    setNewComment('');
  }, [collaboration, newComment]);

  const deleteComment = useCallback(async (commentId: string) => {
    await collaboration.sendAction('comment_deleted', { comment_id: commentId });
    setComments(prev => prev.filter(c => c.id !== commentId));
  }, [collaboration]);

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
    collaboration,
  };
}

export function FindingComments({ findingId, targetName, runId }: FindingCommentsProps) {
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
    collaboration,
  } = useFindingComments(findingId, targetName, runId);

  const renderMentions = (text: string) => {
    const ranges = findMentionRanges(text, teamMembers);
    if (ranges.length === 0) return <span>{text}</span>;
   
    const nodes: React.ReactNode[] = [];
    let cursor = 0;
    ranges.forEach((range, idx) => {
      if (range.start > cursor) {
        nodes.push(<span key={`text-${idx}`}>{text.slice(cursor, range.start)}</span>);
      }
      nodes.push(
   
        <span key={`mention-${idx}`} className="text-[var(--accent)] font-bold">
          {text.slice(range.start, range.end)}
        </span>
      );
      cursor = range.end;
    });
    if (cursor < text.length) {
      nodes.push(<span key="text-tail">{text.slice(cursor)}</span>);
    }
    return nodes;
  };

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleString();
  };

  if (loading) return <div className="finding-comments p-4 text-muted">Loading comments...</div>;

  return (
    <div className="finding-comments">
      {error && <div className="mb-2 text-red-400 text-sm">{error}</div>}
      <div className="mb-3 flex flex-col gap-2">
        <h4 className="comments-title">Comments ({comments.length})</h4>
        <AnalystPresenceIndicator
          analysts={collaboration.presence}
          currentAnalystId={collaboration.analyst.analyst_id}
          connected={collaboration.connected}
        />
      </div>

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
          onChange={e => {
            setNewComment(e.target.value);
            collaboration.broadcastCursor({ area: 'comments', field: 'new-comment', length: e.target.value.length });
          }}
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
      {collaboration.state?.chain && (
        <div className="mt-3 text-[10px] text-muted font-mono">
          Audit chain: {collaboration.state.chain.valid ? 'verified' : 'invalid'} | {collaboration.state.chain.entries} entries | {collaboration.state.chain.latest_hash.slice(0, 12)}
        </div>
      )}
    </div>
  );
}
