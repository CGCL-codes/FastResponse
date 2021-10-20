#include "ext4.h"
#include "ext4_jbd2.h"
#include "ext4_extents.h"
#include "mballoc.h"

void write_tag_block(journal_t *j, journal_block_tag_t *tag,
					 unsigned long long block)
{
	tag->t_blocknr = cpu_to_be32(block & (u32)~0);
	if (jbd2_has_feature_64bit(j))
		tag->t_blocknr_high = cpu_to_be32((block >> 31) >> 1);
}

void journal_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	BUFFER_TRACE(bh, "");
	if (uptodate)
		set_buffer_uptodate(bh);
	else
		clear_buffer_uptodate(bh);
	unlock_buffer(bh);
}

void ext4_fj_init_inode(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	ext4_clear_inode_state(inode, EXT4_STATE_FJ_COMMITTING);
	INIT_LIST_HEAD(&ei->i_fj_list);
	init_waitqueue_head(&ei->i_fj_wait);
	atomic_set(&ei->i_fj_updates, 0);
}

/*
 * FJ commit cleanup routine. This is called after every fj commit and
 * full commit. full is true if we are called after a full commit.
 */
static void ext4_fj_cleanup(journal_t *journal, int full)
{
	struct super_block *sb = journal->j_private;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *iter;
	struct list_head *pos, *n;

	if (full)
		atomic_set(&sbi->s_fj_subtid, 0);

	jbd2_fj_release_bufs(journal);

	spin_lock(&sbi->s_fj_lock);
	list_for_each_safe(pos, n, &sbi->s_fj_q[FJ_Q_MAIN])
	{
		iter = list_entry(pos, struct ext4_inode_info, i_fj_list);
		list_del_init(&iter->i_fj_list);
		ext4_clear_inode_state(&iter->vfs_inode,
							   EXT4_STATE_FJ_COMMITTING);
		/* Make sure EXT4_STATE_FJ_COMMITTING bit is clear */
		smp_mb();
#if (BITS_PER_LONG < 64)
		wake_up_bit(&iter->i_state_flags, EXT4_STATE_FJ_COMMITTING);
#else
		wake_up_bit(&iter->i_flags, EXT4_STATE_FJ_COMMITTING);
#endif
	}

	list_splice_init(&sbi->s_fj_q[FJ_Q_STAGING],
					 &sbi->s_fj_q[FJ_Q_MAIN]);

	sbi->s_mount_state &= ~EXT4_FJ_COMMITTING;

	spin_unlock(&sbi->s_fj_lock);
}

/*
 * Remove inode from fj commit list. If the inode is being committed
 * we wait until inode commit is done.
 */
void ext4_fj_del(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;

	if (!journal)
		return ;

restart:
	spin_lock(&EXT4_SB(inode->i_sb)->s_fj_lock);
	if (list_empty(&ei->i_fj_list)) {
		spin_unlock(&EXT4_SB(inode->i_sb)->s_fj_lock);
		return;
	}

	if (ext4_test_inode_state(inode, EXT4_STATE_FJ_COMMITTING)) {
		wait_queue_head_t *wq;
#if (BITS_PER_LONG < 64)
		DEFINE_WAIT_BIT(wait, &ei->i_state_flags,
				EXT4_STATE_FJ_COMMITTING);
		wq = bit_waitqueue(&ei->i_state_flags,
				   EXT4_STATE_FJ_COMMITTING);
#else
		DEFINE_WAIT_BIT(wait, &ei->i_flags,
				EXT4_STATE_FJ_COMMITTING);
		wq = bit_waitqueue(&ei->i_flags,
				   EXT4_STATE_FJ_COMMITTING);
#endif
		prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		spin_unlock(&EXT4_SB(inode->i_sb)->s_fj_lock);
		schedule();
		finish_wait(wq, &wait.wq_entry);
		goto restart;
	}
	if (!list_empty(&ei->i_fj_list))
		list_del_init(&ei->i_fj_list);
	spin_unlock(&EXT4_SB(inode->i_sb)->s_fj_lock);
}

void ext4_fj_track_inode(struct inode *inode)
{
	tid_t running_txn_tid;
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;

	if (!journal || current->critical != 1)
		return ;

	if (S_ISDIR(inode->i_mode))
		return;

	running_txn_tid = sbi->s_journal ?
		sbi->s_journal->j_commit_sequence + 1 : 0;

	if (running_txn_tid != ei->i_sync_tid)
		ei->i_sync_tid = running_txn_tid;

	spin_lock(&sbi->s_fj_lock);
	if (list_empty(&ei->i_fj_list)){
		if (sbi->s_mount_state & EXT4_FJ_COMMITTING){
			list_add_tail(&ei->i_fj_list,&sbi->s_fj_q[FJ_Q_STAGING]);
		}
		else{
			list_add_tail(&ei->i_fj_list,&sbi->s_fj_q[FJ_Q_MAIN]);
		}
	}
	
	spin_unlock(&sbi->s_fj_lock);
}

// TODO: not used!
void ext4_fj_track_range(struct inode *inode, ext4_lblk_t start, ext4_lblk_t end)
{
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;
	
	if (!journal || current->critical != 1)
		return ;

	if (S_ISDIR(inode->i_mode))
		return;
}

/* Submit data for all the fj commit inodes */
static int ext4_fj_submit_inode_data_all(journal_t *journal)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *ei;
	struct list_head *pos;
	int ret = 0;

	spin_lock(&sbi->s_fj_lock);
	sbi->s_mount_state |= EXT4_FJ_COMMITTING;
	list_for_each(pos, &sbi->s_fj_q[FJ_Q_MAIN])
	{
		ei = list_entry(pos, struct ext4_inode_info, i_fj_list);
		ext4_set_inode_state(&ei->vfs_inode, EXT4_STATE_FJ_COMMITTING);
		while (atomic_read(&ei->i_fj_updates))
		{
			DEFINE_WAIT(wait);

			prepare_to_wait(&ei->i_fj_wait, &wait,
							TASK_UNINTERRUPTIBLE);
			if (atomic_read(&ei->i_fj_updates))
			{
				spin_unlock(&sbi->s_fj_lock);
				schedule();
				spin_lock(&sbi->s_fj_lock);
			}
			finish_wait(&ei->i_fj_wait, &wait);
		}
		spin_unlock(&sbi->s_fj_lock);
		ret = jbd2_submit_inode_data(ei->jinode);
		if (ret)
			return ret;
		spin_lock(&sbi->s_fj_lock);
	}
	spin_unlock(&sbi->s_fj_lock);

	return ret;
}

/* Wait for completion of data for all the fj commit inodes */
static int ext4_fj_wait_inode_data_all(journal_t *journal)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *pos, *n;
	int ret = 0;

	spin_lock(&sbi->s_fj_lock);
	list_for_each_entry_safe(pos, n, &sbi->s_fj_q[FJ_Q_MAIN], i_fj_list)
	{
		if (!ext4_test_inode_state(&pos->vfs_inode,
								   EXT4_STATE_FJ_COMMITTING))
			continue;
		spin_unlock(&sbi->s_fj_lock);

		ret = jbd2_wait_inode_data(journal, pos->jinode);
		if (ret)
			return ret;
		spin_lock(&sbi->s_fj_lock);
	}
	spin_unlock(&sbi->s_fj_lock);

	return 0;
}

// TODO: not used! Since a fsync() invoke by a dictionary, we will commit a normal transaction.
int ext4_sync_dentry(struct inode *inode, int datasync)
{
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int ret = 0;
	tid_t commit_tid = sbi->s_journal->j_running_transaction->t_tid;
	struct dentry *dentry = NULL;

	dentry = hlist_entry(inode->i_dentry.first, struct dentry, d_u.d_alias);

	J_ASSERT(ext4_journal_current_handle() == NULL);

	if (journal->j_commit_sequence >= commit_tid)
	{
		//		printk(KERN_DEBUG "j_commit_sequence >= commit_tid. fsync_out\n");
		goto out;
	}
	if (dentry->d_parent->d_inode && inode->i_ino != EXT4_ROOT_INO && ext4_test_inode_state(dentry->d_parent->d_inode, EXT4_STATE_NEWENTRY))
	{
		ext4_sync_dentry(dentry->d_parent->d_inode, 0);
		ext4_clear_inode_state(dentry->d_parent->d_inode, EXT4_STATE_NEWENTRY);
	}

	{
		struct ext4_iloc iloc;
		struct ext4_inode *raw_inode;
		struct jbd2_ext *jext;
		struct jbd2_inode *jinode = ei->jinode;
		struct buffer_head *bh, *bh_list[100]; // according to bh->bsize - sizeof(header) - sizeof(f_encry) = 4096-12-(4+256+1+1)=478
		journal_header_t *header;
		struct commit_header *commit;
		struct fsync_entry *fj_entry;
		unsigned long long blocknr;
		int size = 1;
		int i = 0;
		struct ext4_extent_header *inode_extent_hdr;
		bool ext_extent = false;

		jbd2_journal_next_log_block(journal, &blocknr);
		bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);

		lock_buffer(bh);
		memset(bh->b_data, 0, journal->j_blocksize);

		header = (journal_header_t *)&bh->b_data[0];
		header->h_magic = cpu_to_be32(JBD2_MAGIC_NUMBER);
		header->h_blocktype = cpu_to_be32(JBD2_FSYNC_BLOCK);
		header->h_sequence = cpu_to_be32(commit_tid);

		bh_list[0] = bh;
		fj_entry = (struct fsync_entry *)(&bh->b_data[0] + sizeof(journal_header_t));
		fj_entry->i_num = cpu_to_be32(inode->i_ino);

		ext4_get_inode_loc(inode, &iloc);
		raw_inode = ext4_raw_inode(&iloc);

		inode_extent_hdr = (struct ext4_extent_header *)&raw_inode->i_block[0];

		memcpy(&fj_entry->raw_inode, raw_inode, sizeof(struct ext4_inode));
		brelse(iloc.bh);

		{
			int tag_bytes = journal_tag_bytes(journal);
			int tag_flag = 0;
			int space_left = bh->b_size - (sizeof(journal_header_t) + sizeof(struct fsync_entry));
			char *tagp = (&bh->b_data[0] + sizeof(journal_header_t) + sizeof(struct fsync_entry));
			bool first_tag = true;
			journal_block_tag_t *tag = NULL;
			ext4_lblk_t block, blocks;
			blocks = inode->i_size >> inode->i_sb->s_blocksize_bits;

			for (block = 0; block < blocks; block++)
			{
				char *mapped_data;
				struct buffer_head *tmp_bh;
				tag_flag = 0;
				tmp_bh = ext4_getblk(NULL, inode, block, 0);
				mapped_data = kmap(tmp_bh->b_page);
				if (*((__be32 *)(mapped_data)) == cpu_to_be32(JBD2_MAGIC_NUMBER))
					tag_flag |= JBD2_FLAG_ESCAPE;
				kunmap(tmp_bh->b_page);

				tag = (journal_block_tag_t *)tagp;
				write_tag_block(journal, tag, tmp_bh->b_blocknr);
				tag->t_flags = cpu_to_be32(tag_flag);
				tagp += tag_bytes;
				space_left -= tag_bytes;

				if (first_tag)
				{
					memcpy(tagp, journal->j_uuid, 16);
					tagp += 16;
					space_left -= 16;
					first_tag = 0;
				}
				else
					tag->t_flags |= cpu_to_be32(JBD2_FLAG_SAME_UUID);

				if (space_left < 0)
				{
					printk(KERN_DEBUG "dentry space_left is over\n");
					BUG();
				}
				brelse(tmp_bh);
			}
			if (jinode)
			{
				spin_lock(&jinode->jext_list_lock);
				list_for_each_entry(jext, &jinode->jext_list, e_list)
				{
					char *mapped_data;
					tag_flag = 0;

					if (!buffer_jbddirty(jext->e_bh))
						continue;
					if (tid_geq(journal->j_commit_sequence, jext->e_trans))
						continue;

					mapped_data = kmap(jext->e_bh->b_page);
					if (*((__be32 *)(mapped_data)) == cpu_to_be32(JBD2_MAGIC_NUMBER))
						tag_flag |= JBD2_FLAG_ESCAPE;

					kunmap(jext->e_bh->b_page);
					tag = (journal_block_tag_t *)tagp;

					write_tag_block(journal, tag, jext->e_bh->b_blocknr);
					tag->t_flags = cpu_to_be32(tag_flag);
					tagp += tag_bytes;
					space_left -= tag_bytes;
					if (first_tag)
					{
						memcpy(tagp, journal->j_uuid, 16);
						tagp += 16;
						space_left -= 16;
						first_tag = 0;
					}
					else
						tag->t_flags |= cpu_to_be32(JBD2_FLAG_SAME_UUID);

					if (space_left < 0)
					{
						printk(KERN_DEBUG "dentry2: space_left is over\n");
						BUG();
					}
				}
				spin_unlock(&jinode->jext_list_lock);
			}
			if (tag)
				tag->t_flags |= cpu_to_be32(JBD2_FLAG_LAST_TAG);
			set_buffer_uptodate(bh);
			bh->b_end_io = journal_end_buffer_io_sync;

			submit_bh(REQ_OP_WRITE, REQ_SYNC | REQ_PRIO | REQ_NOMERGE, bh);
			/* write dentry block */
			for (block = 0; block < blocks; block++)
			{
				char *mapped_data, *tmp;
				struct buffer_head *tmp_bh;

				jbd2_journal_next_log_block(journal, &blocknr);
				bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
				bh_list[size++] = bh;

				tmp_bh = ext4_getblk(NULL, inode, block, 0);

				mapped_data = kmap(tmp_bh->b_page);
				tmp = kmap(bh->b_page);
				memcpy(tmp + offset_in_page(bh->b_data), mapped_data + offset_in_page(tmp_bh->b_data), bh->b_size);
				kunmap(tmp_bh->b_page);
				kunmap(bh->b_page);
				brelse(tmp_bh);

				bh->b_blocknr = blocknr;
				set_buffer_mapped(bh);
				set_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				bh->b_end_io = journal_end_buffer_io_sync;

				lock_buffer(bh);
				submit_bh(REQ_OP_WRITE, REQ_SYNC | REQ_PRIO | REQ_NOMERGE, bh);
			}
			/* write extent */
			if (jinode)
			{
				list_for_each_entry(jext, &jinode->jext_list, e_list)
				{
					char *mapped_data, *tmp;
					struct ext4_extent_header *e_hdr;
					if (!buffer_jbddirty(jext->e_bh))
						continue;

					if (tid_geq(journal->j_commit_sequence, jext->e_trans))
						continue;

					jbd2_journal_next_log_block(journal, &blocknr);
					bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);

					bh_list[size++] = bh;
					e_hdr = (struct ext4_extent_header *)jext->e_bh->b_data;

					mapped_data = jext->e_bh->b_data;
					tmp = kmap(bh->b_page);
					memcpy(tmp, mapped_data, bh->b_size);
					kunmap(bh->b_page);

					bh->b_blocknr = blocknr;
					set_buffer_mapped(bh);
					set_buffer_dirty(bh);
					set_buffer_uptodate(bh);
					bh->b_end_io = journal_end_buffer_io_sync;

					lock_buffer(bh);
					submit_bh(REQ_OP_WRITE, REQ_SYNC | REQ_PRIO | REQ_NOMERGE, bh);
				}
			}
		}
		if (size > 100)
		{
			printk(KERN_DEBUG "dentry: size > 100\n");
			BUG();
		}

		jbd2_journal_next_log_block(journal, &blocknr);

		bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
		//		printk(KERN_DEBUG "ext4_sync_file_inode:blocknr:%lld\n", blocknr);

		lock_buffer(bh);
		memset(bh->b_data, 0, journal->j_blocksize);

		commit = (struct commit_header *)bh->b_data;
		commit->h_magic = cpu_to_be32(JBD2_MAGIC_NUMBER);
		commit->h_blocktype = cpu_to_be32(JBD2_COMMIT_BLOCK);
		commit->h_sequence = cpu_to_be32(commit_tid);

		set_buffer_uptodate(bh);
		bh->b_end_io = journal_end_buffer_io_sync;

		unsigned int write_flags = REQ_SYNC | REQ_PRIO | REQ_NOMERGE;
		if (journal->j_flags & JBD2_BARRIER && !jbd2_has_feature_async_commit(journal))
			write_flags |= REQ_PREFLUSH | REQ_FUA;
		submit_bh(REQ_OP_WRITE, write_flags, bh);

		for (i = 0; i < size; i++)
		{
			if (buffer_locked(bh_list[i]))
			{
				wait_on_buffer(bh_list[i]);
			}
			__brelse(bh_list[i]);
		}

		wait_on_buffer(bh);
		__brelse(bh);
	}
out:
	return ret;
}

static void ext4_fj_commit_dentry_updates(journal_t *journal)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *iter;
	struct list_head *pos;
	struct inode *inode;
	struct dentry *dentry = NULL;

	spin_lock(&sbi->s_fj_lock);
	list_for_each(pos, &sbi->s_fj_q[FJ_Q_MAIN])
	{
		iter = list_entry(pos, struct ext4_inode_info, i_fj_list);
		inode = &iter->vfs_inode;
		dentry = hlist_entry(inode->i_dentry.first, struct dentry, d_u.d_alias);
		if (dentry->d_parent->d_inode && inode->i_ino != EXT4_ROOT_INO && ext4_test_inode_state(dentry->d_parent->d_inode, EXT4_STATE_NEWENTRY))
		{
			//		printk(KERN_DEBUG "ext4_sync_file: sync parent\n");
			spin_unlock(&sbi->s_fj_lock);
			ext4_sync_dentry(dentry->d_parent->d_inode, 0);
			ext4_clear_inode_state(dentry->d_parent->d_inode, EXT4_STATE_NEWENTRY);
			spin_lock(&sbi->s_fj_lock);
		}
	}
	spin_unlock(&sbi->s_fj_lock);
}

static int ext4_fj_commit_inode_updates(journal_t *journal)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_inode_info *iter;
	struct list_head *pos;
	struct inode *inode;
	int ret = 0;
	tid_t commit_tid = sbi->s_journal->j_running_transaction ? 
				sbi->s_journal->j_running_transaction->t_tid :
				sbi->s_journal->j_committing_transaction->t_tid;

	unsigned long long blocknr, first_blocknr;
	struct buffer_head *bh, *bh_extent, *bh_list[100];
	int bh_list_size = 0, write_flags = REQ_SYNC | REQ_PRIO | REQ_NOMERGE;
	journal_header_t *header;
	struct commit_header *commit;
	struct jbd2_inode *jinode;
	int *fj_subtid, *inode_count, tmp_inode_count = 0;
	fsync_entry *fj_entry;

	unsigned int b_size, space_used;
	char *cur_ptr, *mapped_data, *tmp;
	struct ext4_iloc iloc;
	struct ext4_inode *raw_inode;
//	journal_block_tag_t *tag;
	struct jbd2_ext *jext, *next_j;
//	struct ext4_extent_header *e_hdr;
	bool first_extent = true;


	ret = jbd2_fj_get_buf(EXT4_SB(sb)->s_journal, &bh, &blocknr);
	if (ret){
		printk(KERN_DEBUG "fj_commit_inode_updates: no free block1");
		return ret;
	}

	first_blocknr = blocknr;
	bh->b_end_io = journal_end_buffer_io_sync;
	bh_list[bh_list_size++] = bh;
	memset(bh->b_data, 0, journal->j_blocksize);

	// header, fj_subtid, inode_count, fj_entry, (extent_block_index), fj_entry...
	header = (journal_header_t *)&bh_list[0]->b_data[0];
	header->h_magic = cpu_to_be32(JBD2_MAGIC_NUMBER);
	header->h_blocktype = cpu_to_be32(JBD2_FSYNC_BLOCK);
	header->h_sequence = cpu_to_be32(commit_tid);

	fj_subtid = (int *)(&bh_list[0]->b_data[0] + sizeof(journal_header_t));
	*fj_subtid = atomic_read(&sbi->s_fj_subtid);

	inode_count = (int *)(&bh_list[0]->b_data[0] + sizeof(journal_header_t) + sizeof(int));
	b_size = bh_list[0]->b_size;
	space_used = sizeof(journal_header_t) + sizeof(int) + sizeof(int);
	cur_ptr = &bh_list[0]->b_data[0] + space_used;

	spin_lock(&sbi->s_fj_lock);

	list_for_each(pos, &sbi->s_fj_q[FJ_Q_MAIN])
	{
		iter = list_entry(pos, struct ext4_inode_info, i_fj_list);
		inode = &iter->vfs_inode;

		if (!ext4_test_inode_state(inode, EXT4_STATE_FJ_COMMITTING))
			continue;

		spin_unlock(&sbi->s_fj_lock);
		tmp_inode_count++;

		
		// inode's fj_entry
//		fj_entry = (fsync_entry *)cur_ptr;
		space_used += sizeof(fsync_entry);
//		cur_ptr = &bh_list[0]->b_data[0] + space_used;
		if (space_used >= b_size)
		{
			printk(KERN_DEBUG "header space_used is over\n");
			ret = jbd2_fj_get_buf(EXT4_SB(sb)->s_journal, &bh, &blocknr);
			if (ret){
				printk(KERN_DEBUG "fj_commit_inode_updates: no free block0");
				return ret;
			}
			bh_list[bh_list_size++] = bh;
			fj_entry = (fsync_entry *)&bh->b_data[0];
			fj_entry->extra_head_index = (char)(blocknr - first_blocknr);
			space_used = sizeof(fsync_entry);
			cur_ptr = &bh->b_data[0] + space_used;
			printk(KERN_DEBUG "new block space_used: %u\n", space_used);
		}
		else {
			fj_entry = (fsync_entry *)cur_ptr;
			cur_ptr = (char *)fj_entry + sizeof(fsync_entry);
			fj_entry->extra_head_index = 0;
		}
		fj_entry->i_num = cpu_to_be32(inode->i_ino);
		fj_entry->commit_flag = 1;
		fj_entry->extent_block_index = 0;
		ext4_get_inode_loc(inode, &iloc);
		raw_inode = ext4_raw_inode(&iloc);
		memcpy(&fj_entry->raw_inode, raw_inode, sizeof(struct ext4_inode));
		brelse(iloc.bh);
		// init the var that will be used in the loop
		jinode = iter->jinode;
		first_extent = true;
		if (jinode == NULL){
			spin_lock(&sbi->s_fj_lock);
			printk(KERN_DEBUG "jinode is null: %lu", inode->i_ino);
			continue;
		}
		spin_lock(&jinode->jext_list_lock);
		// write inode's extent
		list_for_each_entry(jext, &jinode->jext_list, e_list)
		{
			if (!buffer_jbddirty(jext->e_bh))
				continue;
			if (tid_geq(journal->j_commit_sequence, jext->e_trans))
				continue;
			// write jext to block
			ret = jbd2_fj_get_buf(EXT4_SB(sb)->s_journal, &bh_extent, &blocknr);
			if (ret){
				spin_unlock(&jinode->jext_list_lock);
				printk(KERN_DEBUG "fj_commit_inode_updates: no free block2");
				return ret;
			}
			bh_list[bh_list_size++] = bh_extent;
			if (first_extent)
			{
				fj_entry->commit_flag = 0;
				first_extent = false;
/*				extent_block_index = (unsigned long long *)(cur_ptr);
				space_used += sizeof(unsigned long long);
				cur_ptr = &bh_list[0]->b_data[0] + space_used;
				if (space_used >= b_size)
				{
					spin_unlock(&jinode->jext_list_lock);
					printk(KERN_DEBUG "extent space_used is over\n");
					BUG();
				}
				*extent_block_index = blocknr;
*/
				fj_entry->extent_block_index = (char)(blocknr - first_blocknr);
			}

			mapped_data = jext->e_bh->b_data;
			tmp = kmap(bh_extent->b_page);
			memcpy(tmp, mapped_data, bh_extent->b_size);
			kunmap(bh_extent->b_page);
			bh_extent->b_blocknr = blocknr;

			lock_buffer(bh_extent);
			set_buffer_mapped(bh_extent);
			set_buffer_dirty(bh_extent);
			set_buffer_uptodate(bh_extent);
			bh_extent->b_end_io = journal_end_buffer_io_sync;

			submit_bh(REQ_OP_WRITE, REQ_SYNC | REQ_PRIO | REQ_NOMERGE, bh_extent);

		}
		spin_unlock(&jinode->jext_list_lock);
		spin_lock(&sbi->s_fj_lock);
	}
	spin_unlock(&sbi->s_fj_lock);
	*inode_count = tmp_inode_count;

	lock_buffer(bh_list[0]);
	set_buffer_dirty(bh_list[0]);
	set_buffer_uptodate(bh_list[0]);
	bh_list[0]->b_end_io = journal_end_buffer_io_sync;
	submit_bh(REQ_OP_WRITE, REQ_SYNC | REQ_PRIO | REQ_NOMERGE, bh_list[0]);

	// now submit commit block
	ret = jbd2_fj_get_buf(EXT4_SB(sb)->s_journal, &bh, &blocknr);
	if (ret){
		printk(KERN_DEBUG "fj_commit_inode_updates: no free block3");
		return ret;
	}

	bh_list[bh_list_size++] = bh;
	memset(bh->b_data, 0, journal->j_blocksize);
	commit = (struct commit_header *)bh->b_data;
	commit->h_magic = cpu_to_be32(JBD2_MAGIC_NUMBER);
	commit->h_blocktype = cpu_to_be32(JBD2_COMMIT_BLOCK);
	commit->h_sequence = cpu_to_be32(commit_tid);

	lock_buffer(bh);
	set_buffer_dirty(bh);
	set_buffer_uptodate(bh);
	bh->b_end_io = journal_end_buffer_io_sync;
	if (journal->j_flags & JBD2_BARRIER)
		write_flags |= REQ_FUA | REQ_PREFLUSH;
	submit_bh(REQ_OP_WRITE, write_flags, bh);

//	printk(KERN_DEBUG "bh_list_size: %d", bh_list_size);
	// now wait all buffers
/*	for (i = bh_list_size - 1; i >= 0; i--)
	{
		if (buffer_locked(bh_list[i]))
		{
			wait_on_buffer(bh_list[i]);
		}
printk(KERN_DEBUG "release %d", i);
		__brelse(bh_list[i]);
	}
*/
	jbd2_fj_wait_bufs(journal, bh_list_size);
;
	list_for_each(pos, &sbi->s_fj_q[FJ_Q_MAIN])
	{
		iter = list_entry(pos, struct ext4_inode_info, i_fj_list);
		inode = &iter->vfs_inode;
		jinode = iter->jinode;
		list_for_each_entry_safe(jext, next_j, &jinode->jext_list, e_list) {
			bh2jh(jext->e_bh)->b_modified = 0;
//			printk(KERN_DEBUG "modified-flag clear:%llu", jext->e_bh->b_blocknr);
			list_del_init(&jext->e_list);
			kfree(jext);
		}
		jinode->jext_len = 0;
	}

	return ret;
}

static int ext4_fj_perform_commit(journal_t *journal)
{
	struct blk_plug plug;
	int ret = 0;

	ret = ext4_fj_submit_inode_data_all(journal);
	if (ret)
		return ret;

	ret = ext4_fj_wait_inode_data_all(journal);
	if (ret)
		return ret;

	blk_start_plug(&plug);

//	ext4_fj_commit_dentry_updates(journal);

	ret = ext4_fj_commit_inode_updates(journal);

	blk_finish_plug(&plug);
	return ret;
}

int ext4_fj_commit(journal_t *journal, tid_t commit_tid)
{
	struct super_block *sb = (struct super_block *)(journal->j_private);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int ret, flag = 0;
	int subtid = atomic_read(&sbi->s_fj_subtid);
	struct list_head *pos;
	struct ext4_inode_info *iter;
	struct inode *inode;

	if (current->critical != 1)
		return 0;

	spin_lock(&sbi->s_fj_lock);
	list_for_each(pos, &sbi->s_fj_q[FJ_Q_MAIN])
	{
		iter = list_entry(pos, struct ext4_inode_info, i_fj_list);
		inode = &iter->vfs_inode;
		// Avoid doing iJ for dir and file with uncommitted hard link. just do comman transaction.
		if (S_ISDIR(inode->i_mode) || HAS_UNCOMMITTED_HL(inode))
		{
			printk(KERN_DEBUG "inode:%lu is dir or has uncommited hard link\n", inode->i_ino);
			spin_unlock(&sbi->s_fj_lock);
			ret = jbd2_complete_transaction(journal, commit_tid);
			goto out;
		}
	}
	spin_unlock(&sbi->s_fj_lock);

restart_fj:
	ret = jbd2_fj_begin_commit(journal, commit_tid);
	if (ret == -EALREADY)
	{
		/* There was an ongoing commit, check if we need to restart */
		if (atomic_read(&sbi->s_fj_subtid) <= subtid &&
			commit_tid > journal->j_commit_sequence){
			printk(KERN_DEBUG "there was an ongoing commit:%u %u", current->tgid, current->pid);
			goto restart_fj;
		}
		printk(KERN_DEBUG "has been committed by other thread:%u %u", current->tgid, current->pid);
		goto out;
	}	
	else if (ret)
	{
		printk(KERN_DEBUG "FJ commits only allowed if at least one full commit has been processed and there must be at least one chkpt on the chkpt_list");
		ret = jbd2_complete_transaction(journal, commit_tid);
		goto out;
	}
	ret = ext4_fj_perform_commit(journal);
	if (ret < 0)
	{
		printk(KERN_DEBUG "ext4_fj_perform_commit fail");
		flag = 1;
		goto out;
	}
	atomic_inc(&sbi->s_fj_subtid);
	jbd2_fj_end_commit(journal);
out:
	if(flag){
		printk(KERN_DEBUG "ext4_fj_perform_commit fail: journal area out!");
		jbd2_fj_end_commit_fallback(journal);
	}

	return 0;
}

void ext4_fj_init(struct super_block *sb, journal_t *journal)
{
	journal->j_fj_cleanup_callback = ext4_fj_cleanup;
	if (jbd2_fj_init(journal, EXT4_NUM_FJ_BLKS)) {
		pr_warn("Error while enabling fj commits, turning off.");
//		ext4_clear_feature_fj_commit(sb);
		BUG();
	}
}
